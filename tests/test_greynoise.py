import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from sources.greynoise import GreyNoiseClient


@pytest.fixture
def client():
    return GreyNoiseClient(api_key="test-key")


# -- Successful responses -----------------------------------------------------

@pytest.mark.asyncio
async def test_malicious_ip(client):
    """IP classified as malicious by GreyNoise."""
    mock_response = {
        "ip": "45.148.10.86",
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "unknown",
        "link": "https://viz.greynoise.io/ip/45.148.10.86",
        "last_seen": "2024-01-15",
        "message": "Success",
    }

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_response):
        result = await client.lookup("45.148.10.86", "ip")

    assert result is not None
    assert result["source"] == "greynoise"
    assert result["is_malicious"] is True
    assert result["is_noise"] is False
    assert result["noise"] is True
    assert result["classification"] == "malicious"


@pytest.mark.asyncio
async def test_noise_scanner_ip(client):
    """IP identified as benign mass-scanner (noise but not malicious)."""
    mock_response = {
        "ip": "71.6.135.131",
        "noise": True,
        "riot": False,
        "classification": "benign",
        "name": "Shodan.io",
        "link": "https://viz.greynoise.io/ip/71.6.135.131",
        "last_seen": "2024-01-15",
        "message": "Success",
    }

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_response):
        result = await client.lookup("71.6.135.131", "ip")

    assert result is not None
    assert result["is_malicious"] is False
    assert result["is_noise"] is True
    assert result["noise"] is True
    assert result["classification"] == "benign"
    assert result["name"] == "Shodan.io"


@pytest.mark.asyncio
async def test_riot_ip(client):
    """IP in RIOT dataset (common business services like Google DNS)."""
    mock_response = {
        "ip": "8.8.8.8",
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
        "link": "https://viz.greynoise.io/ip/8.8.8.8",
        "last_seen": "2024-01-15",
        "message": "Success",
    }

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_response):
        result = await client.lookup("8.8.8.8", "ip")

    assert result is not None
    assert result["is_malicious"] is False
    assert result["is_noise"] is False
    assert result["riot"] is True
    assert result["name"] == "Google Public DNS"


# -- Not found / unknown IP ---------------------------------------------------

@pytest.mark.asyncio
async def test_ip_not_seen(client):
    """IP not in GreyNoise dataset -- _request returns the 'not found' body."""
    mock_response = {
        "ip": "192.168.1.1",
        "noise": False,
        "riot": False,
        "classification": "unknown",
        "name": "unknown",
        "link": "",
        "last_seen": "",
        "message": "IP not observed scanning the internet or contained in RIOT data set.",
    }

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_response):
        result = await client.lookup("192.168.1.1", "ip")

    assert result is not None
    assert result["is_malicious"] is False
    assert result["is_noise"] is False
    assert result["classification"] == "unknown"


# -- Non-IP IOC types ---------------------------------------------------------

@pytest.mark.asyncio
async def test_domain_lookup_returns_none(client):
    """GreyNoise only supports IPs; other IOC types should return None immediately."""
    result = await client.lookup("evil.com", "domain")
    assert result is None


@pytest.mark.asyncio
async def test_hash_lookup_returns_none(client):
    result = await client.lookup("abc123def456", "hash")
    assert result is None


# -- Input validation ----------------------------------------------------------

@pytest.mark.asyncio
async def test_invalid_ip_format(client):
    """Malformed IP should be rejected before making any HTTP call."""
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("not-an-ip", "ip")

    assert result is None
    mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_ipv6_valid(client):
    """IPv6 addresses should be accepted."""
    mock_response = {
        "ip": "2607:f8b0:4004:800::200e",
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google",
        "last_seen": "2024-01-15",
        "message": "Success",
    }

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_response):
        result = await client.lookup("2607:f8b0:4004:800::200e", "ip")

    assert result is not None
    assert result["riot"] is True


# -- API errors ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_returns_none_on_failure(client):
    """When _request returns None (after retries exhausted), lookup returns None."""
    with patch.object(client, "_request", new_callable=AsyncMock, return_value=None):
        result = await client.lookup("1.2.3.4", "ip")

    assert result is None


@pytest.mark.asyncio
async def test_retry_on_server_error(client):
    """Verify that _request is called once by lookup (retries are internal to _request).

    The base class _request method handles 500s with exponential backoff.
    We test that lookup correctly propagates the final result.
    """
    # Simulate _request succeeding after internal retries
    mock_response = {
        "ip": "1.2.3.4",
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "unknown",
        "last_seen": "2024-01-15",
        "message": "Success",
    }

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_response):
        result = await client.lookup("1.2.3.4", "ip")

    assert result is not None
    assert result["is_malicious"] is True


@pytest.mark.asyncio
async def test_retry_logic_in_base_request():
    """Test the actual retry behavior in _request with mocked HTTP responses.

    Simulates two 500 errors followed by a 200, verifying exponential backoff.
    """
    client = GreyNoiseClient(api_key="test-key")

    mock_resp_500 = AsyncMock()
    mock_resp_500.status = 500
    mock_resp_500.__aenter__ = AsyncMock(return_value=mock_resp_500)
    mock_resp_500.__aexit__ = AsyncMock(return_value=False)

    mock_resp_200 = AsyncMock()
    mock_resp_200.status = 200
    mock_resp_200.json = AsyncMock(return_value={"ip": "1.2.3.4", "noise": True})
    mock_resp_200.__aenter__ = AsyncMock(return_value=mock_resp_200)
    mock_resp_200.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.request = MagicMock(side_effect=[mock_resp_500, mock_resp_500, mock_resp_200])

    with patch.object(client, "_get_session", new_callable=AsyncMock, return_value=mock_session), \
         patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        result = await client._request("GET", "https://api.greynoise.io/v3/community/1.2.3.4")

    assert result == {"ip": "1.2.3.4", "noise": True}
    assert mock_session.request.call_count == 3
    # Backoff: 1s after first 500, 2s after second 500
    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(1)
    mock_sleep.assert_any_call(2)

    await client.close()


@pytest.mark.asyncio
async def test_retry_exhaustion_returns_none():
    """All retries fail with 500 -- _request returns None."""
    client = GreyNoiseClient(api_key="test-key")

    mock_resp_500 = AsyncMock()
    mock_resp_500.status = 500
    mock_resp_500.__aenter__ = AsyncMock(return_value=mock_resp_500)
    mock_resp_500.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.request = MagicMock(return_value=mock_resp_500)

    with patch.object(client, "_get_session", new_callable=AsyncMock, return_value=mock_session), \
         patch("asyncio.sleep", new_callable=AsyncMock):
        result = await client._request("GET", "https://api.greynoise.io/v3/community/1.2.3.4")

    assert result is None
    assert mock_session.request.call_count == 3

    await client.close()


@pytest.mark.asyncio
async def test_connection_error_triggers_retry():
    """Network-level failures (DNS, connection refused) trigger retries."""
    client = GreyNoiseClient(api_key="test-key")

    mock_resp_200 = AsyncMock()
    mock_resp_200.status = 200
    mock_resp_200.json = AsyncMock(return_value={"ip": "1.2.3.4", "noise": False})
    mock_resp_200.__aenter__ = AsyncMock(return_value=mock_resp_200)
    mock_resp_200.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.request = MagicMock(
        side_effect=[aiohttp.ClientError("Connection refused"), mock_resp_200]
    )

    with patch.object(client, "_get_session", new_callable=AsyncMock, return_value=mock_session), \
         patch("asyncio.sleep", new_callable=AsyncMock):
        result = await client._request("GET", "https://api.greynoise.io/v3/community/1.2.3.4")

    assert result == {"ip": "1.2.3.4", "noise": False}
    assert mock_session.request.call_count == 2

    await client.close()


# -- Configuration ------------------------------------------------------------

def test_is_always_configured():
    """Community API needs no key, so is_configured should always be True."""
    client = GreyNoiseClient(api_key="")
    assert client.is_configured is True


def test_source_name():
    client = GreyNoiseClient()
    assert client.source_name == "greynoise"
    assert client.daily_limit == 0
