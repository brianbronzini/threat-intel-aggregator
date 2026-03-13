import ipaddress
import logging

from core.config import settings
from sources.base import ThreatIntelSource

logger = logging.getLogger(__name__)

COMMUNITY_API_URL = "https://api.greynoise.io/v3/community"


class GreyNoiseClient(ThreatIntelSource):
    """GreyNoise Community API client for IP noise/threat classification.

    GreyNoise identifies IPs mass-scanning the internet, distinguishing
    targeted attacks from background noise. Only supports IP lookups.

    Community API: free, no key required, unlimited queries.
    Response fields: ip, noise, riot, classification, name, link, last_seen, message.
    """

    source_name = "greynoise"
    base_url = COMMUNITY_API_URL
    daily_limit = 0

    def __init__(self, api_key: str = ""):
        super().__init__(api_key or settings.greynoise_api_key)

    @property
    def is_configured(self) -> bool:
        """Community API works without a key, so always configured."""
        return True

    async def lookup(self, indicator: str, ioc_type: str) -> dict | None:
        """Query GreyNoise for IP classification.

        Args:
            indicator: An IPv4 or IPv6 address.
            ioc_type: Must be 'ip'; other types return None.

        Returns:
            Standardized dict with noise/threat classification, or None on failure.
        """
        if ioc_type != "ip":
            return None

        if not self._is_valid_ip(indicator):
            logger.warning("Invalid IP address: %s", indicator)
            return None

        url = f"{self.base_url}/{indicator}"
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key

        data = await self._request("GET", url, headers=headers)
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
        """Convert raw GreyNoise response to a standardized enrichment dict."""
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "unknown")

        is_malicious = classification == "malicious"
        is_noise = noise and not is_malicious

        return {
            "source": "greynoise",
            "is_malicious": is_malicious,
            "is_noise": is_noise,
            "noise": noise,
            "riot": riot,
            "classification": classification,
            "name": data.get("name", "unknown"),
            "last_seen": data.get("last_seen", ""),
            "message": data.get("message", ""),
            "tags": [],
        }
