from unittest.mock import AsyncMock, patch

import pytest

from sources.threatfox import ThreatFoxClient

TEST_API_KEY = "test-threatfox-key"


@pytest.fixture
def client():
    return ThreatFoxClient(api_key=TEST_API_KEY)


def _make_match(
    ioc_type: str = "ip:port",
    threat_type: str = "botnet_cc",
    malware: str = "Emotet",
    confidence: int = 75,
    tags: list[str] | None = None,
    first_seen: str = "2024-01-10 08:00:00 UTC",
    last_seen: str = "2024-01-15 12:00:00 UTC",
) -> dict:
    return {
        "id": "12345",
        "ioc": "1.2.3.4:443",
        "ioc_type": ioc_type,
        "threat_type": threat_type,
        "malware": malware,
        "confidence_level": confidence,
        "tags": tags if tags is not None else ["emotet", "epoch5"],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "reference": "https://example.com/report",
        "reporter": "analyst1",
    }


def _make_response(matches: list[dict] | None = None, query_status: str = "ok") -> dict:
    if matches is None:
        matches = [_make_match()]
    return {"query_status": query_status, "data": matches}


# -- IOC type support ----------------------------------------------------------

@pytest.mark.asyncio
async def test_ip_lookup(client):
    mock_resp = _make_response([_make_match(ioc_type="ip:port")])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result is not None
    assert result["source"] == "threatfox"
    assert result["is_malicious"] is True
    assert result["match_count"] == 1


@pytest.mark.asyncio
async def test_domain_lookup(client):
    mock_resp = _make_response([_make_match(ioc_type="domain")])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("evil.example.com", "domain")

    assert result is not None
    assert result["match_count"] == 1


@pytest.mark.asyncio
async def test_url_lookup(client):
    mock_resp = _make_response([_make_match(ioc_type="url")])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("https://evil.com/payload", "url")

    assert result is not None
    assert result["match_count"] == 1


@pytest.mark.asyncio
async def test_md5_hash_lookup(client):
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    mock_resp = _make_response([_make_match(ioc_type="md5_hash")])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
        result = await client.lookup(md5, "hash")

    assert result is not None
    mock_req.assert_called_once_with(
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        json_body={"query": "search_ioc", "search_term": md5, "exact_match": True},
        headers={"Auth-Key": TEST_API_KEY},
    )


@pytest.mark.asyncio
async def test_sha256_hash_lookup(client):
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    mock_resp = _make_response([_make_match(ioc_type="sha256_hash")])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
        result = await client.lookup(sha256, "hash")

    assert result is not None
    mock_req.assert_called_once_with(
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        json_body={"query": "search_ioc", "search_term": sha256, "exact_match": True},
        headers={"Auth-Key": TEST_API_KEY},
    )


# -- Hash validation -----------------------------------------------------------

@pytest.mark.asyncio
async def test_invalid_hash_length(client):
    """Hash that is neither 32 nor 64 chars should be rejected."""
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup("abc123", "hash")

    assert result is None
    mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_hash_characters(client):
    """Hash with non-hex characters should be rejected."""
    bad_hash = "z" * 32
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        result = await client.lookup(bad_hash, "hash")

    assert result is None
    mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_ioc_type(client):
    result = await client.lookup("something", "invalid")
    assert result is None


# -- Confidence thresholds -----------------------------------------------------

@pytest.mark.asyncio
async def test_confidence_49_not_malicious(client):
    mock_resp = _make_response([_make_match(confidence=49)])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["is_malicious"] is False
    assert result["max_confidence"] == 49


@pytest.mark.asyncio
async def test_confidence_50_is_malicious(client):
    mock_resp = _make_response([_make_match(confidence=50)])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["is_malicious"] is True
    assert result["max_confidence"] == 50


@pytest.mark.asyncio
async def test_confidence_0(client):
    mock_resp = _make_response([_make_match(confidence=0)])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["is_malicious"] is False
    assert result["max_confidence"] == 0


@pytest.mark.asyncio
async def test_confidence_100(client):
    mock_resp = _make_response([_make_match(confidence=100)])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["is_malicious"] is True
    assert result["max_confidence"] == 100


# -- No results ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_result_status(client):
    mock_resp = {"query_status": "no_result", "data": None}

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("8.8.8.8", "ip")

    assert result is not None
    assert result["is_malicious"] is False
    assert result["match_count"] == 0
    assert result["threat_types"] == []
    assert result["malware_families"] == []
    assert result["tags"] == []
    assert result["first_seen"] == ""
    assert result["last_seen"] == ""
    assert result["metadata"] == {"matches": []}


@pytest.mark.asyncio
async def test_ok_status_empty_data(client):
    """query_status is 'ok' but data is an empty list."""
    mock_resp = {"query_status": "ok", "data": []}

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("8.8.8.8", "ip")

    assert result["is_malicious"] is False
    assert result["match_count"] == 0


# -- Multiple matches (aggregation) -------------------------------------------

@pytest.mark.asyncio
async def test_multiple_matches_aggregation(client):
    """Multiple matches should aggregate threat types, malware, tags, and confidence."""
    matches = [
        _make_match(
            threat_type="botnet_cc",
            malware="Emotet",
            confidence=60,
            tags=["emotet", "epoch5"],
            first_seen="2024-01-10 08:00:00 UTC",
            last_seen="2024-01-12 10:00:00 UTC",
        ),
        _make_match(
            threat_type="payload_delivery",
            malware="TrickBot",
            confidence=90,
            tags=["trickbot", "emotet"],
            first_seen="2024-01-05 06:00:00 UTC",
            last_seen="2024-01-15 14:00:00 UTC",
        ),
        _make_match(
            threat_type="botnet_cc",
            malware="Emotet",
            confidence=40,
            tags=["emotet"],
            first_seen="2024-01-08 12:00:00 UTC",
            last_seen="2024-01-11 09:00:00 UTC",
        ),
    ]
    mock_resp = _make_response(matches)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["match_count"] == 3
    assert result["max_confidence"] == 90
    assert result["is_malicious"] is True
    # Unique, sorted
    assert result["threat_types"] == ["botnet_cc", "payload_delivery"]
    assert result["malware_families"] == ["Emotet", "TrickBot"]
    assert result["tags"] == ["emotet", "epoch5", "trickbot"]
    # Earliest first_seen, latest last_seen
    assert result["first_seen"] == "2024-01-05 06:00:00 UTC"
    assert result["last_seen"] == "2024-01-15 14:00:00 UTC"
    assert len(result["metadata"]["matches"]) == 3


@pytest.mark.asyncio
async def test_multiple_matches_all_low_confidence(client):
    """Multiple matches all below threshold should not be malicious."""
    matches = [
        _make_match(confidence=20),
        _make_match(confidence=49),
        _make_match(confidence=10),
    ]
    mock_resp = _make_response(matches)

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["is_malicious"] is False
    assert result["max_confidence"] == 49


# -- Null/missing fields in matches -------------------------------------------

@pytest.mark.asyncio
async def test_match_with_null_tags(client):
    match = _make_match(tags=None)
    match["tags"] = None  # Simulate actual null from API
    mock_resp = _make_response([match])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["tags"] == []


@pytest.mark.asyncio
async def test_match_with_missing_fields(client):
    """Match with missing optional fields should use defaults."""
    minimal_match = {"confidence_level": 70}
    mock_resp = _make_response([minimal_match])

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.lookup("1.2.3.4", "ip")

    assert result["is_malicious"] is True
    assert result["threat_types"] == []
    assert result["malware_families"] == []
    assert result["first_seen"] == ""
    assert result["last_seen"] == ""


# -- API errors ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_failure_returns_none(client):
    with patch.object(client, "_request", new_callable=AsyncMock, return_value=None):
        result = await client.lookup("1.2.3.4", "ip")

    assert result is None


@pytest.mark.asyncio
async def test_request_sends_correct_body(client):
    mock_resp = _make_response(query_status="no_result")

    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
        await client.lookup("evil.com", "domain")

    mock_req.assert_called_once_with(
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        json_body={"query": "search_ioc", "search_term": "evil.com", "exact_match": True},
        headers={"Auth-Key": TEST_API_KEY},
    )


# -- Configuration ------------------------------------------------------------

def test_configured_with_api_key():
    client = ThreatFoxClient(api_key="my-key")
    assert client.is_configured is True
    assert client.api_key == "my-key"


def test_not_configured_without_api_key():
    with patch("sources.threatfox.settings") as mock_settings:
        mock_settings.threatfox_api_key = ""
        client = ThreatFoxClient()
    assert client.is_configured is False
    assert client.api_key == ""


def test_no_rate_limit():
    client = ThreatFoxClient(api_key="key")
    assert client.daily_limit == 0


def test_source_name():
    client = ThreatFoxClient(api_key="key")
    assert client.source_name == "threatfox"


def test_uses_settings_key_by_default():
    with patch("sources.threatfox.settings") as mock_settings:
        mock_settings.threatfox_api_key = "from-settings"
        client = ThreatFoxClient()
    assert client.api_key == "from-settings"


@pytest.mark.asyncio
async def test_no_auth_header_without_key():
    """When no API key is set, headers dict should be empty."""
    with patch("sources.threatfox.settings") as mock_settings:
        mock_settings.threatfox_api_key = ""
        client = ThreatFoxClient()

    mock_resp = _make_response(query_status="no_result")
    with patch.object(client, "_request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
        await client.lookup("1.2.3.4", "ip")

    mock_req.assert_called_once_with(
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        json_body={"query": "search_ioc", "search_term": "1.2.3.4", "exact_match": True},
        headers={},
    )
