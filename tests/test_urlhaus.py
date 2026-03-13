from unittest.mock import AsyncMock, patch

import pytest

from sources.urlhaus import URLhausClient


@pytest.fixture
def client():
    return URLhausClient()


_UNSET = object()


def _make_response(
    query_status: str = "ok",
    url_status: str | None = "online",
    threat: str | None = "malware_download",
    tags: list[str] | None = _UNSET,
    date_added: str = "2024-01-15 10:00:00 UTC",
) -> dict:
    """Build a realistic URLhaus response."""
    return {
        "query_status": query_status,
        "id": "12345",
        "url": "https://evil.com/payload.exe",
        "url_status": url_status,
        "host": "evil.com",
        "date_added": date_added,
        "threat": threat,
        "blacklists": {"spamhaus_dbl": "not listed"},
        "tags": ["elf", "mirai"] if tags is _UNSET else tags,
    }


# -- Online (malicious) URL ----------------------------------------------------

@pytest.mark.asyncio
async def test_online_malware_url(client):
    mock_resp = _make_response(
        url_status="online", threat="malware_download", tags=["elf", "mirai"]
    )

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("https://evil.com/payload.exe", "url")

    assert result is not None
    assert result["source"] == "urlhaus"
    assert result["is_malicious"] is True
    assert result["threat_type"] == "malware_download"
    assert result["status"] == "online"
    assert result["tags"] == ["elf", "mirai"]
    assert result["date_added"] == "2024-01-15 10:00:00 UTC"


# -- Offline URL ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_offline_url(client):
    mock_resp = _make_response(url_status="offline")

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("https://taken-down.com/bad.exe", "url")

    assert result["is_malicious"] is False
    assert result["status"] == "offline"


# -- No results (URL not in database) -----------------------------------------

@pytest.mark.asyncio
async def test_no_results(client):
    mock_resp = {"query_status": "no_results"}

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("https://clean-site.com/index.html", "url")

    assert result is not None
    assert result["is_malicious"] is False
    assert result["status"] == "not_found"
    assert result["threat_type"] == ""
    assert result["tags"] == []


# -- Null fields in response ---------------------------------------------------

@pytest.mark.asyncio
async def test_null_url_status(client):
    """url_status can be null in the API response."""
    mock_resp = _make_response(url_status=None, threat=None, tags=None)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("https://mystery.com/file", "url")

    assert result["is_malicious"] is False
    assert result["status"] == "unknown"
    assert result["threat_type"] == ""
    assert result["tags"] == []


# -- IOC type filtering --------------------------------------------------------

@pytest.mark.asyncio
async def test_ip_type_rejected(client):
    result = await client.lookup("1.2.3.4", "ip")
    assert result is None


@pytest.mark.asyncio
async def test_domain_type_rejected(client):
    result = await client.lookup("evil.com", "domain")
    assert result is None


@pytest.mark.asyncio
async def test_hash_type_rejected(client):
    result = await client.lookup("abc123def456", "hash")
    assert result is None


# -- URL validation ------------------------------------------------------------

@pytest.mark.asyncio
async def test_invalid_url_no_scheme(client):
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("evil.com/payload.exe", "url")

    assert result is None
    mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_url_no_host(client):
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("http://", "url")

    assert result is None
    mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_url_ftp_scheme(client):
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("ftp://files.example.com/bad.bin", "url")

    assert result is None
    mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_valid_http_url(client):
    mock_resp = _make_response(url_status="online")

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("http://evil.com/payload", "url")

    assert result is not None
    assert result["is_malicious"] is True


@pytest.mark.asyncio
async def test_valid_https_url(client):
    mock_resp = _make_response(url_status="offline")

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("https://evil.com/payload", "url")

    assert result is not None


# -- API errors ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_failure_returns_none(client):
    with patch.object(client, "_request", new_callable=AsyncMock, return_value=None):
        result = await client.lookup("https://evil.com/bad", "url")

    assert result is None


@pytest.mark.asyncio
async def test_request_sends_post_with_url(client):
    mock_resp = _make_response()

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
        await client.lookup("https://evil.com/payload.exe", "url")

    mock_req.assert_called_once_with(
        "POST",
        "https://urlhaus-api.abuse.ch/v1/url/",
        form_data={"url": "https://evil.com/payload.exe"},
    )


# -- Configuration ------------------------------------------------------------

def test_always_configured():
    client = URLhausClient()
    assert client.is_configured is True


def test_no_rate_limit():
    client = URLhausClient()
    assert client.daily_limit == 0


def test_source_name():
    client = URLhausClient()
    assert client.source_name == "urlhaus"


def test_ignores_api_key():
    """API key arg should be ignored -- URLhaus doesn't need one."""
    client = URLhausClient(api_key="should-be-ignored")
    assert client.api_key == ""
