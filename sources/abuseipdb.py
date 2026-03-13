import ipaddress
import logging

from core.config import settings
from sources.base import ThreatIntelSource

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"

# Threshold above which an IP is considered malicious
MALICIOUS_THRESHOLD = 75


class AbuseIPDBClient(ThreatIntelSource):
    """AbuseIPDB API client for IP abuse/reputation lookups.

    AbuseIPDB aggregates community-reported abuse data for IP addresses.
    Only supports IP lookups. Requires an API key.

    Free tier: 1,000 requests/day.
    Docs: https://docs.abuseipdb.com/#check-endpoint
    """

    source_name = "abuseipdb"
    base_url = API_URL
    daily_limit = settings.rate_limit_abuseipdb

    def __init__(self, api_key: str = ""):
        super().__init__(api_key or settings.abuseipdb_api_key)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, indicator: str, ioc_type: str) -> dict | None:
        """Query AbuseIPDB for IP reputation data.

        Args:
            indicator: An IPv4 or IPv6 address.
            ioc_type: Must be 'ip'; other types return None.

        Returns:
            Standardized dict with abuse confidence score and report data,
            or None on failure or missing API key.
        """
        if ioc_type != "ip":
            return None

        if not self.is_configured:
            logger.warning("AbuseIPDB API key not configured, skipping")
            return None

        if not self._is_valid_ip(indicator):
            logger.warning("Invalid IP address for AbuseIPDB: %s", indicator)
            return None

        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": indicator, "maxAgeInDays": "90"}

        data = await self._request("GET", self.base_url, headers=headers, params=params)
        if data is None:
            return None

        return self._normalize(data)

    @staticmethod
    def _is_valid_ip(indicator: str) -> bool:
        """Validate that the indicator is a well-formed IP address."""
        try:
            ipaddress.ip_address(indicator)
            return True
        except ValueError:
            return False

    @staticmethod
    def _normalize(data: dict) -> dict:
        """Convert raw AbuseIPDB response to a standardized enrichment dict.

        AbuseIPDB wraps the result in a 'data' key.
        """
        inner = data.get("data", {})
        confidence = inner.get("abuseConfidenceScore", 0)

        return {
            "source": "abuseipdb",
            "is_malicious": confidence > MALICIOUS_THRESHOLD,
            "confidence_score": confidence,
            "total_reports": inner.get("totalReports", 0),
            "last_reported_at": inner.get("lastReportedAt"),
            "is_whitelisted": inner.get("isWhitelisted", False),
            "country_code": inner.get("countryCode", ""),
            "usage_type": inner.get("usageType", ""),
            "isp": inner.get("isp", ""),
            "domain": inner.get("domain", ""),
        }
