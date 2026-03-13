"""Main enrichment engine that orchestrates source queries and scoring."""

import asyncio
import ipaddress
import logging
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.config import settings
from core.scoring import calculate_reputation
from db.cache import CacheManager
from db.models import IOCRecord
from sources.abuseipdb import AbuseIPDBClient
from sources.greynoise import GreyNoiseClient
from sources.ipinfo import IPinfoClient
from sources.threatfox import ThreatFoxClient
from sources.urlhaus import URLhausClient
from sources.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)

# Which sources apply to each IOC type
SOURCE_MAP = {
    "ip": ["greynoise", "abuseipdb", "virustotal", "threatfox", "ipinfo"],
    "domain": ["threatfox"],
    "url": ["urlhaus", "threatfox"],
    "hash": ["virustotal", "threatfox"],
}


class ThreatIntelAggregator:
    """Orchestrates IOC enrichment across multiple threat intel sources."""

    def __init__(
        self,
        cache: CacheManager | None = None,
        sources: dict | None = None,
    ):
        self.cache = cache or CacheManager()
        self.sources = sources or {
            "greynoise": GreyNoiseClient(api_key=settings.greynoise_api_key),
            "abuseipdb": AbuseIPDBClient(api_key=settings.abuseipdb_api_key),
            "virustotal": VirusTotalClient(api_key=settings.virustotal_api_key),
            "ipinfo": IPinfoClient(api_key=settings.ipinfo_api_key),
            "threatfox": ThreatFoxClient(),
            "urlhaus": URLhausClient(),
        }

    async def close(self) -> None:
        """Close all source HTTP sessions."""
        for source in self.sources.values():
            await source.close()

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        if not domain or " " in domain or len(domain) > 253:
            return False
        pattern = re.compile(
            r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
        )
        return bool(pattern.match(domain))

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    @staticmethod
    def _is_valid_hash(hash_str: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}", hash_str))

    def _validate(self, indicator: str, ioc_type: str) -> None:
        """Raise ValueError if the indicator doesn't match the IOC type."""
        validators = {
            "ip": self._is_valid_ip,
            "domain": self._is_valid_domain,
            "url": self._is_valid_url,
            "hash": self._is_valid_hash,
        }
        if ioc_type not in validators:
            raise ValueError(f"Unknown IOC type: {ioc_type!r}")
        if not validators[ioc_type](indicator):
            raise ValueError(
                f"Invalid {ioc_type} indicator: {indicator!r}"
            )

    # ------------------------------------------------------------------
    # Main enrichment method
    # ------------------------------------------------------------------

    async def enrich_ioc(
        self,
        indicator: str,
        ioc_type: str,
        force_refresh: bool = False,
    ) -> dict:
        """Enrich an IOC with threat intelligence from all applicable sources."""
        self._validate(indicator, ioc_type)
        start_ms = time.monotonic()

        # 1. Check cache
        if not force_refresh:
            try:
                cached = await self.cache.get(indicator)
                if cached is not None:
                    result = cached.to_dict()
                    result["metadata"] = {
                        **result.get("metadata", {}),
                        "cached": True,
                        "cache_age_seconds": int(
                            (datetime.now(timezone.utc) - cached.last_updated).total_seconds()
                        ),
                        "query_time_ms": int((time.monotonic() - start_ms) * 1000),
                    }
                    return result
            except Exception:
                logger.warning("Cache read failed for %s, querying sources", indicator)

        # 2. Determine applicable sources
        applicable = SOURCE_MAP.get(ioc_type, [])

        # 3. Query sources in parallel
        async def _query(name: str) -> tuple[str, dict | None]:
            client = self.sources.get(name)
            if client is None:
                return name, None
            try:
                return name, await client.lookup(indicator, ioc_type)
            except Exception as exc:
                logger.warning("Source %s failed for %s: %s", name, indicator, exc)
                return name, None

        pairs = await asyncio.gather(*[_query(name) for name in applicable])
        source_results = {name: result for name, result in pairs}

        # 4. Score
        scoring = calculate_reputation(source_results)

        # 5. Extract enrichment from ipinfo
        enrichment = {}
        ipinfo_data = source_results.get("ipinfo")
        if ipinfo_data:
            for key in ("country", "country_code", "city", "region", "org", "asn",
                        "latitude", "longitude", "timezone", "postal"):
                if key in ipinfo_data:
                    enrichment[key] = ipinfo_data[key]

        # 6. Extract threat details from threatfox / urlhaus
        threat_details: dict = {"threat_types": [], "malware_families": [], "tags": []}
        tf_data = source_results.get("threatfox")
        if tf_data:
            threat_details["threat_types"] = tf_data.get("threat_types", [])
            threat_details["malware_families"] = tf_data.get("malware_families", [])
            threat_details["tags"].extend(tf_data.get("tags", []))
        uh_data = source_results.get("urlhaus")
        if uh_data:
            threat_details["tags"].extend(uh_data.get("tags", []))

        query_time_ms = int((time.monotonic() - start_ms) * 1000)
        now_iso = datetime.now(timezone.utc).isoformat()

        enriched = {
            "indicator": indicator,
            "type": ioc_type,
            "reputation": scoring["reputation"],
            "confidence_score": scoring["confidence_score"],
            "is_malicious": scoring["reputation"] in ("MALICIOUS", "SUSPICIOUS"),
            "sources_consulted": scoring["sources_consulted"],
            "sources_flagged": scoring["sources_flagged"],
            "enrichment": enrichment,
            "threat_details": threat_details,
            "metadata": {
                "cached": False,
                "cache_age_seconds": 0,
                "query_time_ms": query_time_ms,
                "timestamp": now_iso,
                "sources": source_results,
            },
            "score_breakdown": scoring["score_breakdown"],
        }

        # 7. Store in cache
        try:
            record = IOCRecord(
                indicator=indicator,
                ioc_type=ioc_type,
                reputation=scoring["reputation"],
                confidence_score=scoring["confidence_score"],
                sources=scoring["sources_consulted"],
                metadata=enriched["metadata"],
            )
            await self.cache.store(record)
        except Exception:
            logger.warning("Cache store failed for %s", indicator)

        return enriched
