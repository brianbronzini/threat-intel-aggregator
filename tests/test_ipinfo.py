from unittest.mock import AsyncMock, patch

import pytest

from sources.ipinfo import IPinfoClient


@pytest.fixture
def client():
    return IPinfoClient(api_key="test-ipinfo-token")


def _make_response(
    ip: str = "8.8.8.8",
    city: str = "Mountain View",
    region: str = "California",
    country: str = "United States",
    country_code: str = "US",
    loc: str = "37.4056,-122.0775",
    org: str = "Google LLC",
    asn: str = "AS15169",
    postal: str = "94043",
    timezone: str = "America/Los_Angeles",
    bogon: bool = False,
) -> dict:
    """Build a realistic IPinfo Lite response."""
    if bogon:
        return {"ip": ip, "bogon": True}
    return {
        "ip": ip,
        "city": city,
        "region": region,
        "country": country,
        "country_code": country_code,
        "loc": loc,
        "org": org,
        "asn": asn,
        "postal": postal,
        "timezone": timezone,
    }


# -- Full response -------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_response(client):
    mock_resp = _make_response()

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ):
        result = await client.lookup("8.8.8.8", "ip")

    assert result is not None
    assert result["source"] == "ipinfo"
    assert result["is_malicious"] is False
    assert result["is_bogon"] is False
    assert result["country"] == "United States"
    assert result["country_code"] == "US"
    assert result["city"] == "Mountain View"
    assert result["region"] == "California"
    assert result["postal"] == "94043"
    assert result["org"] == "Google LLC"
    assert result["asn"] == "AS15169"
    assert result["latitude"] == "37.4056"
    assert result["longitude"] == "-122.0775"
    assert result["timezone"] == "America/Los_Angeles"


# -- Minimal response ---------------------------------------------------------


@pytest.mark.asyncio
async def test_minimal_response(client):
    """Response with only IP and country_code -- other fields missing."""
    mock_resp = {"ip": "1.2.3.4", "country_code": "DE"}

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["country_code"] == "DE"
    assert result["country"] == ""
    assert result["city"] == ""
    assert result["region"] == ""
    assert result["org"] == ""
    assert result["asn"] == ""
    assert result["latitude"] == ""
    assert result["longitude"] == ""
    assert result["timezone"] == ""


# -- Bogon/private IP ---------------------------------------------------------


@pytest.mark.asyncio
async def test_bogon_private_ip(client):
    mock_resp = _make_response(ip="192.168.1.1", bogon=True)

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ):
        result = await client.lookup("192.168.1.1", "ip")

    assert result is not None
    assert result["is_bogon"] is True
    assert result["is_malicious"] is False
    assert result["country"] == ""
    assert result["country_code"] == ""
    assert result["org"] == ""
    assert result["asn"] == ""


# -- is_malicious always False -------------------------------------------------


@pytest.mark.asyncio
async def test_is_malicious_always_false(client):
    mock_resp = _make_response()

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["is_malicious"] is False


@pytest.mark.asyncio
async def test_bogon_is_malicious_false(client):
    mock_resp = _make_response(bogon=True)

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ):
        result = await client.lookup("10.0.0.1", "ip")

    assert result["is_malicious"] is False


# -- ASN field -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_asn_from_response(client):
    """Lite API returns asn as a direct field."""
    mock_resp = _make_response(asn="AS13335")

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ):
        result = await client.lookup("1.1.1.1", "ip")

    assert result["asn"] == "AS13335"


@pytest.mark.asyncio
async def test_asn_missing_defaults_empty(client):
    mock_resp = {"ip": "1.2.3.4"}

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["asn"] == ""


# -- Lat/long parsing ---------------------------------------------------------


def test_parse_loc_standard():
    assert IPinfoClient._parse_loc("37.4056,-122.0775") == ("37.4056", "-122.0775")


def test_parse_loc_with_spaces():
    assert IPinfoClient._parse_loc("37.4056, -122.0775") == ("37.4056", "-122.0775")


def test_parse_loc_empty():
    assert IPinfoClient._parse_loc("") == ("", "")


def test_parse_loc_no_comma():
    assert IPinfoClient._parse_loc("37.4056") == ("", "")


# -- IOC type filtering --------------------------------------------------------


@pytest.mark.asyncio
async def test_domain_rejected(client):
    result = await client.lookup("example.com", "domain")
    assert result is None


@pytest.mark.asyncio
async def test_hash_rejected(client):
    result = await client.lookup("abc123", "hash")
    assert result is None


@pytest.mark.asyncio
async def test_url_rejected(client):
    result = await client.lookup("https://example.com", "url")
    assert result is None


# -- IP validation -------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_ip(client):
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("not-an-ip", "ip")

    assert result is None
    mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_ipv6_accepted(client):
    mock_resp = _make_response(ip="2607:f8b0:4004:800::200e", country_code="US")

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ):
        result = await client.lookup("2607:f8b0:4004:800::200e", "ip")

    assert result is not None
    assert result["country_code"] == "US"


# -- API token validation -----------------------------------------------------


def test_not_configured_without_token():
    with patch("sources.ipinfo.settings") as mock_settings:
        mock_settings.ipinfo_api_key = ""
        client = IPinfoClient(api_key="")
    assert client.is_configured is False


def test_configured_with_token():
    client = IPinfoClient(api_key="real-token")
    assert client.is_configured is True


@pytest.mark.asyncio
async def test_missing_token_skips_lookup():
    """Lookup should return None immediately when no token is set."""
    with patch("sources.ipinfo.settings") as mock_settings:
        mock_settings.ipinfo_api_key = ""
        client = IPinfoClient(api_key="")

    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("1.2.3.4", "ip")

    assert result is None
    mock_req.assert_not_called()


# -- Auth header ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_bearer_auth_header(client):
    mock_resp = _make_response()

    with patch.object(
        client, "_request", new_callable=AsyncMock, return_value=mock_resp
    ) as mock_req:
        await client.lookup("8.8.8.8", "ip")

    mock_req.assert_called_once_with(
        "GET",
        "https://api.ipinfo.io/lite/8.8.8.8",
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer test-ipinfo-token",
        },
    )


# -- Rate limits ---------------------------------------------------------------


def test_unlimited_rate_limit():
    """Lite tier has no rate limit."""
    client = IPinfoClient(api_key="token")
    assert client.daily_limit == 0


# -- API errors ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_failure_returns_none(client):
    with patch.object(client, "_request", new_callable=AsyncMock, return_value=None):
        result = await client.lookup("1.2.3.4", "ip")

    assert result is None


# -- Source attributes ---------------------------------------------------------


def test_source_name():
    client = IPinfoClient()
    assert client.source_name == "ipinfo"


def test_base_url():
    client = IPinfoClient()
    assert client.base_url == "https://api.ipinfo.io/lite"
