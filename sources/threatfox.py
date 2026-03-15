import logging

from core.config import settings
from sources.base import ThreatIntelSource

logger = logging.getLogger(__name__)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

MALICIOUS_CONFIDENCE_THRESHOLD = 50

VALID_IOC_TYPES = {"ip", "domain", "hash", "url"}


class ThreatFoxClient(ThreatIntelSource):
    """ThreatFox API client for IOC lookups.

    Requires free Auth-Key from https://abuse.ch/account/register/
    Docs: https://threatfox.abuse.ch/api/
    """

    source_name = "threatfox"
    base_url = API_URL
    daily_limit = 0

    def __init__(self, api_key: str = ""):
        super().__init__(api_key or settings.threatfox_api_key)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, indicator: str, ioc_type: str) -> dict | None:
        """Query ThreatFox for IOC matches across all indicator types.

        Args:
            indicator: The IOC value (IP, domain, hash, or URL).
            ioc_type: One of 'ip', 'domain', 'hash', 'url'.

        Returns:
            Standardized dict with aggregated match data, or None on failure.
        """
        if ioc_type not in VALID_IOC_TYPES:
            return None

        search_term = self._prepare_search_term(indicator, ioc_type)
        if search_term is None:
            return None

        body = {"query": "search_ioc", "search_term": search_term, "exact_match": True}
        headers = {"Auth-Key": self.api_key} if self.api_key else {}
        data = await self._request(
            "POST", self.base_url, json_body=body, headers=headers
        )
        if data is None:
            return None

        return self._normalize(data)

    @staticmethod
    def _prepare_search_term(indicator: str, ioc_type: str) -> str | None:
        """Validate and prepare the search term for ThreatFox.

        For hashes, validates length matches MD5 (32) or SHA256 (64).
        """
        if ioc_type == "hash":
            hex_chars = set("0123456789abcdefABCDEF")
            if not all(c in hex_chars for c in indicator):
                logger.warning("Invalid hash characters: %s", indicator)
                return None
            if len(indicator) not in (32, 64):
                logger.warning(
                    "Invalid hash length %d (expected 32 for MD5 or 64 for SHA256): %s",
                    len(indicator),
                    indicator,
                )
                return None
        return indicator

    @staticmethod
    def _normalize(data: dict) -> dict:
        """Convert raw ThreatFox response to a standardized enrichment dict.

        Aggregates data across all matches: unique threat types, malware families,
        combined tags, and the highest confidence level.
        """
        query_status = data.get("query_status", "no_result")

        if query_status != "ok" or not data.get("data"):
            return {
                "source": "threatfox",
                "is_malicious": False,
                "threat_types": [],
                "malware_families": [],
                "max_confidence": 0,
                "match_count": 0,
                "first_seen": "",
                "last_seen": "",
                "tags": [],
                "metadata": {"matches": []},
            }

        matches = data["data"]
        threat_types: set[str] = set()
        malware_families: set[str] = set()
        all_tags: set[str] = set()
        max_confidence = 0
        first_seen_dates: list[str] = []
        last_seen_dates: list[str] = []

        for match in matches:
            if threat_type := match.get("threat_type"):
                threat_types.add(threat_type)
            if malware := match.get("malware"):
                malware_families.add(malware)
            for tag in match.get("tags") or []:
                if tag:
                    all_tags.add(tag)

            confidence = match.get("confidence_level", 0)
            if confidence > max_confidence:
                max_confidence = confidence

            if fs := match.get("first_seen"):
                first_seen_dates.append(fs)
            if ls := match.get("last_seen"):
                last_seen_dates.append(ls)

        first_seen_dates.sort()
        last_seen_dates.sort()

        return {
            "source": "threatfox",
            "is_malicious": max_confidence >= MALICIOUS_CONFIDENCE_THRESHOLD,
            "threat_types": sorted(threat_types),
            "malware_families": sorted(malware_families),
            "max_confidence": max_confidence,
            "match_count": len(matches),
            "first_seen": first_seen_dates[0] if first_seen_dates else "",
            "last_seen": last_seen_dates[-1] if last_seen_dates else "",
            "tags": sorted(all_tags),
            "metadata": {"matches": matches},
        }
