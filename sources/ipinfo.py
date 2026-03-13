import ipaddress
import logging

from core.config import settings
from sources.base import ThreatIntelSource

logger = logging.getLogger(__name__)

# IPinfo Lite (free tier) -- unlimited requests
API_URL = "https://api.ipinfo.io/lite"


class IPinfoClient(ThreatIntelSource):
    """IPinfo Lite API client for IP geolocation and network context.

    Provides enrichment data (location, ASN, org) rather than threat detection.
    is_malicious is always False.

    IPinfo Lite: free, unlimited requests, requires API token.
    Auth: Bearer header or ?token= query param.
    Docs: https://ipinfo.io/developers/ip-to-geolocation-api
    """

    source_name = "ipinfo"
    base_url = API_URL
    daily_limit = 0  # Lite tier is unlimited

    def __init__(self, api_key: str = ""):
        super().__init__(api_key or settings.ipinfo_api_key)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, indicator: str, ioc_type: str) -> dict | None:
        """Query IPinfo Lite for geolocation and network context.

        Args:
            indicator: An IPv4 or IPv6 address.
            ioc_type: Must be 'ip'; other types return None.

        Returns:
            Standardized dict with geo/network enrichment, or None on failure.
        """
        if ioc_type != "ip":
            return None

        if not self.is_configured:
            logger.warning("IPinfo API token not configured, skipping")
            return None

        if not self._is_valid_ip(indicator):
            logger.warning("Invalid IP address for IPinfo: %s", indicator)
            return None

        url = f"{self.base_url}/{indicator}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

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
    def _parse_loc(loc: str) -> tuple[str, str]:
        """Parse 'lat,long' string into separate values."""
        if not loc or "," not in loc:
            return ("", "")
        parts = loc.split(",", 1)
        return (parts[0].strip(), parts[1].strip())

    @staticmethod
    def _normalize(data: dict) -> dict:
        """Convert raw IPinfo Lite response to a standardized enrichment dict.

        Lite response fields include: ip, city, region, country, country_code,
        loc, org, asn, postal, timezone, and possibly bogon for private IPs.
        """
        is_bogon = data.get("bogon", False)

        if is_bogon:
            return {
                "source": "ipinfo",
                "is_malicious": False,
                "is_bogon": True,
                "country": "",
                "country_code": "",
                "city": "",
                "region": "",
                "postal": "",
                "org": "",
                "asn": "",
                "latitude": "",
                "longitude": "",
                "timezone": "",
            }

        loc = data.get("loc", "")
        latitude, longitude = IPinfoClient._parse_loc(loc)

        return {
            "source": "ipinfo",
            "is_malicious": False,
            "is_bogon": False,
            "country": data.get("country", ""),
            "country_code": data.get("country_code", ""),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "postal": data.get("postal", ""),
            "org": data.get("org", ""),
            "asn": data.get("asn", ""),
            "latitude": latitude,
            "longitude": longitude,
            "timezone": data.get("timezone", ""),
        }
