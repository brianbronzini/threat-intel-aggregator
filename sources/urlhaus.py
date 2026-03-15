import logging
from urllib.parse import urlparse

from sources.base import ThreatIntelSource

logger = logging.getLogger(__name__)

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhausClient(ThreatIntelSource):
    """URLhaus API client for malware URL lookups.

    URLhaus tracks malware distribution URLs reported by the security community.
    Only supports URL lookups. No API key or rate limits.

    Docs: https://urlhaus-api.abuse.ch/#urlinfo
    """

    source_name = "urlhaus"
    base_url = API_URL
    daily_limit = 0

    def __init__(self, api_key: str = ""):
        super().__init__("")

    @property
    def is_configured(self) -> bool:
        return True

    async def lookup(self, indicator: str, ioc_type: str) -> dict | None:
        """Query URLhaus for malware URL information.

        Args:
            indicator: A full URL (e.g., https://evil.com/payload.exe).
            ioc_type: Must be 'url'; other types return None.

        Returns:
            Standardized dict with threat classification, or None on failure.
        """
        if ioc_type != "url":
            return None

        if not self._is_valid_url(indicator):
            logger.warning("Invalid URL for URLhaus: %s", indicator)
            return None

        # URLhaus expects form-encoded POST data, not JSON
        data = await self._request("POST", self.base_url, form_data={"url": indicator})
        if data is None:
            return None

        return self._normalize(data)

    @staticmethod
    def _is_valid_url(indicator: str) -> bool:
        """Validate that the indicator looks like an HTTP/HTTPS URL."""
        try:
            parsed = urlparse(indicator)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        except ValueError:
            return False

    @staticmethod
    def _normalize(data: dict) -> dict:
        """Convert raw URLhaus response to a standardized enrichment dict."""
        query_status = data.get("query_status", "no_results")

        if query_status == "no_results":
            return {
                "source": "urlhaus",
                "is_malicious": False,
                "threat_type": "",
                "status": "not_found",
                "tags": [],
                "date_added": "",
            }

        url_status = data.get("url_status") or "unknown"

        return {
            "source": "urlhaus",
            "is_malicious": url_status == "online",
            "threat_type": data.get("threat", "") or "",
            "status": url_status,
            "tags": data.get("tags") or [],
            "date_added": data.get("date_added", ""),
        }
