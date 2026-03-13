from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from sources.abuseipdb import AbuseIPDBClient


@pytest.fixture
def client():
    return AbuseIPDBClient(api_key="test-key-abc")


def _make_response(
    confidence: int = 0,
    total_reports: int = 0,
    last_reported: str | None = None,
    whitelisted: bool = False,
    country: str = "US",
    usage_type: str = "Data Center/Web Hosting/Transit",
) -> dict:
    """Build a realistic AbuseIPDB API response."""
    return {
        "data": {
            "ipAddress": "1.2.3.4",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": whitelisted,
            "abuseConfidenceScore": confidence,
            "countryCode": country,
            "usageType": usage_type,
            "isp": "Example ISP",
            "domain": "example.com",
            "totalReports": total_reports,
            "numDistinctUsers": total_reports,
            "lastReportedAt": last_reported,
        }
    }


# -- Confidence score thresholds -----------------------------------------------

@pytest.mark.asyncio
async def test_high_confidence_malicious(client):
    """abuseConfidenceScore > 75 should flag as malicious."""
    mock_resp = _make_response(confidence=92, total_reports=347, last_reported="2024-01-15T10:00:00+00:00")

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("45.148.10.86", "ip")

    assert result is not None
    assert result["source"] == "abuseipdb"
    assert result["is_malicious"] is True
    assert result["confidence_score"] == 92
    assert result["total_reports"] == 347
    assert result["last_reported_at"] == "2024-01-15T10:00:00+00:00"


@pytest.mark.asyncio
async def test_medium_confidence_not_malicious(client):
    """abuseConfidenceScore 50-75 is suspicious but not malicious."""
    mock_resp = _make_response(confidence=62, total_reports=15)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("203.0.113.50", "ip")

    assert result is not None
    assert result["is_malicious"] is False
    assert result["confidence_score"] == 62
    assert result["total_reports"] == 15


@pytest.mark.asyncio
async def test_low_confidence_clean(client):
    """abuseConfidenceScore < 50 is not malicious."""
    mock_resp = _make_response(confidence=5, total_reports=1)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("198.51.100.10", "ip")

    assert result is not None
    assert result["is_malicious"] is False
    assert result["confidence_score"] == 5


@pytest.mark.asyncio
async def test_zero_confidence(client):
    """abuseConfidenceScore of 0 with no reports."""
    mock_resp = _make_response(confidence=0, total_reports=0)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("8.8.8.8", "ip")

    assert result is not None
    assert result["is_malicious"] is False
    assert result["confidence_score"] == 0
    assert result["total_reports"] == 0
    assert result["last_reported_at"] is None


@pytest.mark.asyncio
async def test_boundary_75_not_malicious(client):
    """Exactly 75 should NOT be malicious (threshold is > 75)."""
    mock_resp = _make_response(confidence=75)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("10.0.0.1", "ip")

    assert result["is_malicious"] is False


@pytest.mark.asyncio
async def test_boundary_76_is_malicious(client):
    """76 should be malicious (> 75)."""
    mock_resp = _make_response(confidence=76)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("10.0.0.2", "ip")

    assert result["is_malicious"] is True


# -- Whitelisted IP ------------------------------------------------------------

@pytest.mark.asyncio
async def test_whitelisted_ip(client):
    """Whitelisted IPs should have is_whitelisted=True regardless of score."""
    mock_resp = _make_response(confidence=0, whitelisted=True)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("8.8.4.4", "ip")

    assert result is not None
    assert result["is_whitelisted"] is True
    assert result["is_malicious"] is False


# -- Metadata extraction -------------------------------------------------------

@pytest.mark.asyncio
async def test_full_metadata(client):
    """All metadata fields should be extracted from the response."""
    mock_resp = _make_response(
        confidence=88,
        total_reports=200,
        last_reported="2024-01-10T08:00:00+00:00",
        country="RU",
        usage_type="Fixed Line ISP",
    )

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("5.6.7.8", "ip")

    assert result["country_code"] == "RU"
    assert result["usage_type"] == "Fixed Line ISP"
    assert result["isp"] == "Example ISP"
    assert result["domain"] == "example.com"


# -- Non-IP IOC types ----------------------------------------------------------

@pytest.mark.asyncio
async def test_domain_returns_none(client):
    result = await client.lookup("evil.com", "domain")
    assert result is None


@pytest.mark.asyncio
async def test_hash_returns_none(client):
    result = await client.lookup("abc123", "hash")
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
    mock_resp = _make_response(confidence=30, country="DE")

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("2001:db8::1", "ip")

    assert result is not None
    assert result["confidence_score"] == 30


# -- API key validation --------------------------------------------------------

def test_not_configured_without_key():
    client = AbuseIPDBClient(api_key="")
    assert client.is_configured is False


def test_configured_with_key():
    client = AbuseIPDBClient(api_key="real-key")
    assert client.is_configured is True


@pytest.mark.asyncio
async def test_missing_api_key_skips_lookup():
    """Lookup should return None immediately when no API key is set."""
    client = AbuseIPDBClient(api_key="")

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
async def test_request_passes_correct_headers_and_params(client):
    """Verify the correct headers and query params are sent."""
    mock_resp = _make_response(confidence=10)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
        await client.lookup("9.9.9.9", "ip")

    mock_req.assert_called_once_with(
        "GET",
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": "test-key-abc", "Accept": "application/json"},
        params={"ipAddress": "9.9.9.9", "maxAgeInDays": "90"},
    )


@pytest.mark.asyncio
async def test_retry_on_server_error(client):
    """Verify retry behavior through the base class _request with mocked HTTP."""
    mock_resp_500 = AsyncMock()
    mock_resp_500.status = 500
    mock_resp_500.__aenter__ = AsyncMock(return_value=mock_resp_500)
    mock_resp_500.__aexit__ = AsyncMock(return_value=False)

    mock_resp_200 = AsyncMock()
    mock_resp_200.status = 200
    mock_resp_200.json = AsyncMock(return_value=_make_response(confidence=50))
    mock_resp_200.__aenter__ = AsyncMock(return_value=mock_resp_200)
    mock_resp_200.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.request = MagicMock(side_effect=[mock_resp_500, mock_resp_200])

    with patch.object(client, "_get_session", new_callable=AsyncMock, return_value=mock_session), \
         patch.object(client, "_check_rate_limit", new_callable=AsyncMock, return_value=True), \
         patch.object(client, "_record_request", new_callable=AsyncMock), \
         patch("asyncio.sleep", new_callable=AsyncMock):
        result = await client._request("GET", "https://api.abuseipdb.com/api/v2/check")

    assert result == _make_response(confidence=50)
    assert mock_session.request.call_count == 2

    await client.close()


@pytest.mark.asyncio
async def test_rate_limit_blocks_request(client):
    """When rate limit is exhausted, _request should return None without HTTP call."""
    mock_session = AsyncMock()

    with patch.object(client, "_check_rate_limit", new_callable=AsyncMock, return_value=False):
        result = await client._request("GET", "https://api.abuseipdb.com/api/v2/check")

    assert result is None


# -- Source attributes ---------------------------------------------------------

def test_source_name():
    client = AbuseIPDBClient(api_key="key")
    assert client.source_name == "abuseipdb"


def test_daily_limit():
    client = AbuseIPDBClient(api_key="key")
    assert client.daily_limit == 1000
