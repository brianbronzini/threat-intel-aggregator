import ipaddress
import logging
import time
from collections import deque

from core.config import settings
from sources.base import ThreatIntelSource

logger = logging.getLogger(__name__)

API_URL = "https://www.virustotal.com/api/v3/ip_addresses"

# VT public API: 4 requests/minute, 500 requests/day
REQUESTS_PER_MINUTE = 4
MINUTE_WINDOW = 60

MALICIOUS_THRESHOLD = 5


class VirusTotalClient(ThreatIntelSource):
    """VirusTotal API client for multi-engine IP analysis.

    VirusTotal aggregates results from 70+ antivirus engines and URL/domain
    scanners. Only supports IP lookups. Requires an API key.

    Public API enforces dual rate limits:
      - 500 requests/day (tracked in DB via RateLimitTracker)
      - 4 requests/minute (tracked in-memory via sliding window)
    Both limits are checked before every request. If either is exceeded,
    the request is skipped and the specific limit is logged.

    Docs: https://docs.virustotal.com/reference/ip-info
    """

    source_name = "virustotal"
    base_url = API_URL
    daily_limit = settings.rate_limit_virustotal

    def __init__(self, api_key: str = ""):
        super().__init__(api_key or settings.virustotal_api_key)
        self._minute_timestamps: deque[float] = deque()

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    # -- Dual rate limiting ----------------------------------------------------
    # Overrides base class methods so both limits are enforced inside _request().

    def _check_minute_rate(self) -> bool:
        """Return True if under the per-minute sliding window limit."""
        now = time.monotonic()
        while self._minute_timestamps and now - self._minute_timestamps[0] > MINUTE_WINDOW:
            self._minute_timestamps.popleft()
        return len(self._minute_timestamps) < REQUESTS_PER_MINUTE

    def _record_minute_request(self) -> None:
        """Record a timestamp for per-minute tracking."""
        self._minute_timestamps.append(time.monotonic())

    async def _check_rate_limit(self) -> bool:
        """Check both daily and per-minute limits before a request.

        The daily limit is persisted in SQLite (survives restarts).
        The per-minute limit uses an in-memory sliding window.
        """
        if not self._check_minute_rate():
            logger.warning(
                "VirusTotal per-minute rate limit hit (%d/%d in last %ds)",
                REQUESTS_PER_MINUTE, REQUESTS_PER_MINUTE, MINUTE_WINDOW,
            )
            return False

        daily_ok = await super()._check_rate_limit()
        if not daily_ok:
            logger.warning(
                "VirusTotal daily rate limit hit (%d/day)", self.daily_limit
            )
            return False

        return True

    async def _record_request(self) -> None:
        """Increment both the daily DB counter and the minute sliding window."""
        self._record_minute_request()
        await super()._record_request()

    # -- Lookup ----------------------------------------------------------------

    async def lookup(self, indicator: str, ioc_type: str) -> dict | None:
        """Query VirusTotal for multi-engine IP analysis.

        Args:
            indicator: An IPv4 or IPv6 address.
            ioc_type: Must be 'ip'; other types return None.

        Returns:
            Standardized dict with detection stats and metadata,
            or None on failure, missing API key, or rate limit hit.
        """
        if ioc_type != "ip":
            return None

        if not self.is_configured:
            logger.warning("VirusTotal API key not configured, skipping")
            return None

        if not self._is_valid_ip(indicator):
            logger.warning("Invalid IP address for VirusTotal: %s", indicator)
            return None

        url = f"{self.base_url}/{indicator}"
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}

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
        """Convert raw VirusTotal response to a standardized enrichment dict."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        detection_rate = round((malicious / total) * 100, 1) if total > 0 else 0.0

        return {
            "source": "virustotal",
            "is_malicious": malicious > MALICIOUS_THRESHOLD,
            "positives": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "detection_rate": detection_rate,
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "network": attrs.get("network", ""),
        }
