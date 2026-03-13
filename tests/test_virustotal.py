import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sources.virustotal import VirusTotalClient, REQUESTS_PER_MINUTE, MINUTE_WINDOW


@pytest.fixture
def client():
    return VirusTotalClient(api_key="test-vt-key")


def _make_response(
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 70,
    undetected: int = 3,
    country: str = "US",
    as_owner: str = "GOOGLE",
    network: str = "8.8.8.0/24",
) -> dict:
    """Build a realistic VirusTotal IP lookup response."""
    return {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "country": country,
                "as_owner": as_owner,
                "network": network,
            },
        }
    }


# -- Detection count thresholds ------------------------------------------------

@pytest.mark.asyncio
async def test_zero_detections(client):
    mock_resp = _make_response(malicious=0, harmless=70, undetected=3)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("8.8.8.8", "ip")

    assert result is not None
    assert result["source"] == "virustotal"
    assert result["is_malicious"] is False
    assert result["positives"] == 0
    assert result["total"] == 73
    assert result["detection_rate"] == 0.0


@pytest.mark.asyncio
async def test_low_detections_not_malicious(client):
    mock_resp = _make_response(malicious=3, harmless=65, undetected=5)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["is_malicious"] is False
    assert result["positives"] == 3


@pytest.mark.asyncio
async def test_boundary_5_not_malicious(client):
    """Exactly 5 malicious -- NOT malicious (threshold is > 5)."""
    mock_resp = _make_response(malicious=5, harmless=60, undetected=8)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("10.0.0.1", "ip")

    assert result["is_malicious"] is False
    assert result["positives"] == 5


@pytest.mark.asyncio
async def test_boundary_6_is_malicious(client):
    """6 malicious -- IS malicious (> 5)."""
    mock_resp = _make_response(malicious=6, harmless=60, undetected=7)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("10.0.0.2", "ip")

    assert result["is_malicious"] is True
    assert result["positives"] == 6


@pytest.mark.asyncio
async def test_high_detections(client):
    mock_resp = _make_response(malicious=10, suspicious=3, harmless=55, undetected=5)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("45.148.10.86", "ip")

    assert result["is_malicious"] is True
    assert result["positives"] == 10
    assert result["suspicious"] == 3
    assert result["total"] == 73
    assert result["detection_rate"] == round((10 / 73) * 100, 1)


# -- Suspicious-only results --------------------------------------------------

@pytest.mark.asyncio
async def test_suspicious_only_not_malicious(client):
    mock_resp = _make_response(malicious=0, suspicious=15, harmless=50, undetected=8)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("203.0.113.50", "ip")

    assert result["is_malicious"] is False
    assert result["positives"] == 0
    assert result["suspicious"] == 15


# -- Detection rate calculation ------------------------------------------------

@pytest.mark.asyncio
async def test_detection_rate_percentage(client):
    mock_resp = _make_response(malicious=7, suspicious=0, harmless=63, undetected=0)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("5.6.7.8", "ip")

    assert result["detection_rate"] == 10.0  # 7/70 = 10%


@pytest.mark.asyncio
async def test_detection_rate_zero_total(client):
    mock_resp = _make_response(malicious=0, suspicious=0, harmless=0, undetected=0)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("192.0.2.1", "ip")

    assert result["detection_rate"] == 0.0
    assert result["total"] == 0


# -- Metadata extraction -------------------------------------------------------

@pytest.mark.asyncio
async def test_full_metadata(client):
    mock_resp = _make_response(malicious=0, country="DE", as_owner="Hetzner Online GmbH", network="5.9.0.0/16")

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("5.9.10.11", "ip")

    assert result["country"] == "DE"
    assert result["as_owner"] == "Hetzner Online GmbH"
    assert result["network"] == "5.9.0.0/16"


@pytest.mark.asyncio
async def test_missing_metadata_defaults(client):
    mock_resp = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}}}}

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("10.0.0.1", "ip")

    assert result["country"] == ""
    assert result["as_owner"] == ""
    assert result["network"] == ""


# -- Non-IP IOC types ----------------------------------------------------------

@pytest.mark.asyncio
async def test_domain_returns_none(client):
    result = await client.lookup("evil.com", "domain")
    assert result is None


@pytest.mark.asyncio
async def test_hash_returns_none(client):
    result = await client.lookup("abc123def456", "hash")
    assert result is None


@pytest.mark.asyncio
async def test_url_returns_none(client):
    result = await client.lookup("https://evil.com/payload", "url")
    assert result is None


# -- Input validation ----------------------------------------------------------

@pytest.mark.asyncio
async def test_invalid_ip_format(client):
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("not-an-ip", "ip")

    assert result is None
    mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_ipv6_accepted(client):
    mock_resp = _make_response(malicious=1, country="JP")

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("2001:db8::1", "ip")

    assert result is not None
    assert result["positives"] == 1


# -- API key validation --------------------------------------------------------

def test_not_configured_without_key():
    client = VirusTotalClient(api_key="")
    assert client.is_configured is False


def test_configured_with_key():
    client = VirusTotalClient(api_key="real-key")
    assert client.is_configured is True


@pytest.mark.asyncio
async def test_missing_api_key_skips_lookup():
    client = VirusTotalClient(api_key="")

    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("1.2.3.4", "ip")

    assert result is None
    mock_req.assert_not_called()


# -- API errors ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_failure_returns_none(client):
    with patch.object(client, "_request", new_callable=AsyncMock, return_value=None):
        result = await client.lookup("1.2.3.4", "ip")

    assert result is None


@pytest.mark.asyncio
async def test_request_passes_correct_headers(client):
    mock_resp = _make_response()

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
        await client.lookup("9.9.9.9", "ip")

    mock_req.assert_called_once_with(
        "GET",
        "https://www.virustotal.com/api/v3/ip_addresses/9.9.9.9",
        headers={"x-apikey": "test-vt-key", "Accept": "application/json"},
    )


# -- Retry on server error -----------------------------------------------------

@pytest.mark.asyncio
async def test_retry_on_500(client):
    mock_resp_500 = AsyncMock()
    mock_resp_500.status = 500
    mock_resp_500.__aenter__ = AsyncMock(return_value=mock_resp_500)
    mock_resp_500.__aexit__ = AsyncMock(return_value=False)

    mock_resp_200 = AsyncMock()
    mock_resp_200.status = 200
    mock_resp_200.json = AsyncMock(return_value=_make_response(malicious=2))
    mock_resp_200.__aenter__ = AsyncMock(return_value=mock_resp_200)
    mock_resp_200.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.request = MagicMock(side_effect=[mock_resp_500, mock_resp_200])

    with patch.object(client, "_get_session", new_callable=AsyncMock, return_value=mock_session), \
         patch.object(client, "_check_rate_limit", new_callable=AsyncMock, return_value=True), \
         patch.object(client, "_record_request", new_callable=AsyncMock), \
         patch("asyncio.sleep", new_callable=AsyncMock):
        result = await client._request("GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4")

    assert result == _make_response(malicious=2)
    assert mock_session.request.call_count == 2

    await client.close()


# ==============================================================================
# DUAL RATE LIMITING TESTS
# ==============================================================================

# -- Per-minute sliding window -------------------------------------------------

class TestMinuteRateLimit:
    """Tests for the per-minute sliding window (4 req/min)."""

    def test_allows_under_limit(self):
        client = VirusTotalClient(api_key="key")
        assert client._check_minute_rate() is True
        client._record_minute_request()
        client._record_minute_request()
        client._record_minute_request()
        assert client._check_minute_rate() is True  # 3 of 4

    def test_allows_exactly_at_limit(self):
        """4th request should still be allowed (limit is 4)."""
        client = VirusTotalClient(api_key="key")
        for _ in range(3):
            client._record_minute_request()
        assert client._check_minute_rate() is True  # 4th is ok

    def test_blocks_over_limit(self):
        """5th request within the window should be blocked."""
        client = VirusTotalClient(api_key="key")
        for _ in range(REQUESTS_PER_MINUTE):
            client._record_minute_request()
        assert client._check_minute_rate() is False

    def test_window_expires_old_timestamps(self):
        """Timestamps older than 60s should be evicted, freeing quota."""
        client = VirusTotalClient(api_key="key")
        old_time = time.monotonic() - MINUTE_WINDOW - 1

        for _ in range(REQUESTS_PER_MINUTE):
            client._minute_timestamps.append(old_time)

        assert client._check_minute_rate() is True
        assert len(client._minute_timestamps) == 0

    def test_partial_window_expiry(self):
        """Only timestamps older than the window should be evicted."""
        client = VirusTotalClient(api_key="key")
        old_time = time.monotonic() - MINUTE_WINDOW - 1
        recent_time = time.monotonic()

        client._minute_timestamps.append(old_time)
        client._minute_timestamps.append(old_time)
        client._minute_timestamps.append(recent_time)
        client._minute_timestamps.append(recent_time)

        # 2 old evicted, 2 recent remain -- under limit of 4
        assert client._check_minute_rate() is True
        assert len(client._minute_timestamps) == 2


# -- Daily rate limit ----------------------------------------------------------

class TestDailyRateLimit:
    """Tests for the daily limit (500/day) via the base class RateLimitTracker."""

    @pytest.mark.asyncio
    async def test_daily_limit_blocks_via_check_rate_limit(self):
        """When daily limit is exhausted, _check_rate_limit returns False."""
        client = VirusTotalClient(api_key="key")

        with patch(
            "sources.base.ThreatIntelSource._check_rate_limit",
            new_callable=AsyncMock, return_value=False,
        ):
            result = await client._check_rate_limit()

        assert result is False

    @pytest.mark.asyncio
    async def test_daily_limit_allows_when_under(self):
        """When daily limit has quota, and minute is ok, should allow."""
        client = VirusTotalClient(api_key="key")

        with patch(
            "sources.base.ThreatIntelSource._check_rate_limit",
            new_callable=AsyncMock, return_value=True,
        ):
            result = await client._check_rate_limit()

        assert result is True


# -- Both limits enforced simultaneously --------------------------------------

class TestDualRateLimiting:
    """Tests that both limits are checked and enforced together."""

    @pytest.mark.asyncio
    async def test_minute_checked_before_daily(self):
        """Per-minute limit should be checked first. If it fails, daily is not queried."""
        client = VirusTotalClient(api_key="key")
        for _ in range(REQUESTS_PER_MINUTE):
            client._record_minute_request()

        with patch(
            "sources.base.ThreatIntelSource._check_rate_limit",
            new_callable=AsyncMock,
        ) as daily_mock:
            result = await client._check_rate_limit()

        assert result is False
        # Daily check should NOT have been called since minute failed first
        daily_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_daily_checked_when_minute_ok(self):
        """When minute limit is fine, daily limit should still be checked."""
        client = VirusTotalClient(api_key="key")

        with patch(
            "sources.base.ThreatIntelSource._check_rate_limit",
            new_callable=AsyncMock, return_value=True,
        ) as daily_mock:
            result = await client._check_rate_limit()

        assert result is True
        daily_mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_both_limits_ok_allows_request(self):
        """Request should proceed when both limits have quota."""
        client = VirusTotalClient(api_key="key")
        mock_resp = _make_response(malicious=2)

        with patch.object(client, "_check_rate_limit", new_callable=AsyncMock, return_value=True), \
             patch.object(client, "_record_request", new_callable=AsyncMock):
            with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
                result = await client.lookup("1.2.3.4", "ip")

        assert result is not None
        assert result["positives"] == 2

    @pytest.mark.asyncio
    async def test_minute_limit_blocks_lookup(self):
        """When per-minute limit is hit, lookup returns None via _request."""
        client = VirusTotalClient(api_key="key")
        for _ in range(REQUESTS_PER_MINUTE):
            client._record_minute_request()

        # _check_rate_limit (overridden) will fail on minute check
        with patch(
            "sources.base.ThreatIntelSource._check_rate_limit",
            new_callable=AsyncMock, return_value=True,
        ):
            result = await client.lookup("1.2.3.4", "ip")

        assert result is None

    @pytest.mark.asyncio
    async def test_daily_limit_blocks_lookup(self):
        """When daily limit is hit (but minute is fine), lookup returns None."""
        client = VirusTotalClient(api_key="key")

        with patch(
            "sources.base.ThreatIntelSource._check_rate_limit",
            new_callable=AsyncMock, return_value=False,
        ):
            result = await client.lookup("1.2.3.4", "ip")

        assert result is None

    @pytest.mark.asyncio
    async def test_rapid_requests_hit_minute_before_daily(self):
        """5 rapid requests: first 4 succeed, 5th blocked by minute limit.

        Uses the real _request flow (with mocked HTTP) so both _check_rate_limit
        and _record_request execute, populating the minute sliding window.
        """
        client = VirusTotalClient(api_key="key")
        vt_resp = _make_response(malicious=1)

        mock_http_resp = AsyncMock()
        mock_http_resp.status = 200
        mock_http_resp.json = AsyncMock(return_value=vt_resp)
        mock_http_resp.__aenter__ = AsyncMock(return_value=mock_http_resp)
        mock_http_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.request = MagicMock(return_value=mock_http_resp)

        results = []
        with patch.object(client, "_get_session", new_callable=AsyncMock, return_value=mock_session), \
             patch("sources.base.ThreatIntelSource._check_rate_limit", new_callable=AsyncMock, return_value=True), \
             patch("sources.base.ThreatIntelSource._record_request", new_callable=AsyncMock):
            for i in range(5):
                result = await client.lookup(f"1.2.3.{i}", "ip")
                results.append(result)

        # First 4 succeed (minute window fills: 0, 1, 2, 3)
        for r in results[:4]:
            assert r is not None
            assert r["positives"] == 1

        # 5th blocked by per-minute limit
        assert results[4] is None
        assert mock_session.request.call_count == 4

        await client.close()

    @pytest.mark.asyncio
    async def test_record_request_increments_both(self):
        """_record_request should call both minute record and daily (super) record."""
        client = VirusTotalClient(api_key="key")
        assert len(client._minute_timestamps) == 0

        with patch(
            "sources.base.ThreatIntelSource._record_request",
            new_callable=AsyncMock,
        ) as daily_record:
            await client._record_request()

        assert len(client._minute_timestamps) == 1
        daily_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_minute_resets_after_window(self):
        """After 60s, the minute window clears and requests are allowed again."""
        client = VirusTotalClient(api_key="key")

        # Fill up the minute window with old timestamps
        old_time = time.monotonic() - MINUTE_WINDOW - 1
        for _ in range(REQUESTS_PER_MINUTE):
            client._minute_timestamps.append(old_time)

        # Minute check should pass (old timestamps evicted)
        with patch(
            "sources.base.ThreatIntelSource._check_rate_limit",
            new_callable=AsyncMock, return_value=True,
        ):
            result = await client._check_rate_limit()

        assert result is True


# -- Source attributes ---------------------------------------------------------

def test_source_name():
    client = VirusTotalClient(api_key="key")
    assert client.source_name == "virustotal"


def test_daily_limit():
    client = VirusTotalClient(api_key="key")
    assert client.daily_limit == 500
