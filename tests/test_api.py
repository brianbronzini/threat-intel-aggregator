"""Tests for the FastAPI routes."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.routes import set_aggregator
from main import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _enriched_result(indicator="8.8.8.8", ioc_type="ip", reputation="CLEAN", score=0):
    return {
        "indicator": indicator,
        "type": ioc_type,
        "reputation": reputation,
        "confidence_score": score,
        "is_malicious": reputation in ("MALICIOUS", "SUSPICIOUS"),
        "sources_consulted": ["greynoise", "abuseipdb"],
        "sources_flagged": [],
        "enrichment": {"country": "US", "org": "Google LLC"},
        "threat_details": {"threat_types": [], "malware_families": [], "tags": []},
        "metadata": {
            "cached": False,
            "cache_age_seconds": 0,
            "query_time_ms": 42,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": {},
        },
        "score_breakdown": {
            "greynoise_points": 0,
            "abuseipdb_points": 0,
            "virustotal_points": 0,
            "threatfox_points": 0,
            "urlhaus_points": 0,
            "total": score,
        },
    }


@pytest.fixture()
def mock_aggregator():
    agg = MagicMock()
    agg.enrich_ioc = AsyncMock(return_value=_enriched_result())
    agg.close = AsyncMock()
    set_aggregator(agg)
    yield agg
    set_aggregator(None)


@pytest.fixture()
def client():
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_has_status_and_timestamp(self, client):
        data = client.get("/health").json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


# ---------------------------------------------------------------------------
# Enrich endpoint
# ---------------------------------------------------------------------------

class TestEnrich:
    def test_enrich_valid_ip(self, client, mock_aggregator):
        resp = client.post("/enrich", json={"indicator": "8.8.8.8", "ioc_type": "ip"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["indicator"] == "8.8.8.8"
        assert data["type"] == "ip"
        mock_aggregator.enrich_ioc.assert_called_once_with(
            indicator="8.8.8.8", ioc_type="ip", force_refresh=False,
        )

    def test_enrich_domain(self, client, mock_aggregator):
        mock_aggregator.enrich_ioc.return_value = _enriched_result(
            indicator="evil.com", ioc_type="domain",
        )
        resp = client.post("/enrich", json={"indicator": "evil.com", "ioc_type": "domain"})
        assert resp.status_code == 200
        assert resp.json()["type"] == "domain"

    def test_enrich_url(self, client, mock_aggregator):
        mock_aggregator.enrich_ioc.return_value = _enriched_result(
            indicator="https://evil.com/bad", ioc_type="url",
        )
        resp = client.post("/enrich", json={
            "indicator": "https://evil.com/bad", "ioc_type": "url",
        })
        assert resp.status_code == 200
        assert resp.json()["type"] == "url"

    def test_enrich_hash(self, client, mock_aggregator):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        mock_aggregator.enrich_ioc.return_value = _enriched_result(
            indicator=h, ioc_type="hash",
        )
        resp = client.post("/enrich", json={"indicator": h, "ioc_type": "hash"})
        assert resp.status_code == 200
        assert resp.json()["type"] == "hash"

    def test_enrich_force_refresh(self, client, mock_aggregator):
        resp = client.post("/enrich", json={
            "indicator": "8.8.8.8", "ioc_type": "ip", "force_refresh": True,
        })
        assert resp.status_code == 200
        mock_aggregator.enrich_ioc.assert_called_once_with(
            indicator="8.8.8.8", ioc_type="ip", force_refresh=True,
        )

    def test_enrich_invalid_indicator_returns_400(self, client, mock_aggregator):
        mock_aggregator.enrich_ioc.side_effect = ValueError("Invalid ip indicator: 'not-an-ip'")
        resp = client.post("/enrich", json={"indicator": "not-an-ip", "ioc_type": "ip"})
        assert resp.status_code == 400
        assert "Invalid ip" in resp.json()["detail"]

    def test_enrich_invalid_type_returns_422(self, client):
        resp = client.post("/enrich", json={"indicator": "8.8.8.8", "ioc_type": "email"})
        assert resp.status_code == 422

    def test_enrich_missing_indicator_returns_422(self, client):
        resp = client.post("/enrich", json={"ioc_type": "ip"})
        assert resp.status_code == 422

    def test_enrich_missing_type_returns_422(self, client):
        resp = client.post("/enrich", json={"indicator": "8.8.8.8"})
        assert resp.status_code == 422

    def test_enrich_internal_error_returns_500(self, client, mock_aggregator):
        mock_aggregator.enrich_ioc.side_effect = RuntimeError("something broke")
        resp = client.post("/enrich", json={"indicator": "8.8.8.8", "ioc_type": "ip"})
        assert resp.status_code == 500
        assert resp.json()["detail"] == "Internal server error"

    def test_enrich_result_structure(self, client, mock_aggregator):
        resp = client.post("/enrich", json={"indicator": "8.8.8.8", "ioc_type": "ip"})
        data = resp.json()
        for key in [
            "indicator", "type", "reputation", "confidence_score",
            "is_malicious", "sources_consulted", "sources_flagged",
            "enrichment", "threat_details", "metadata", "score_breakdown",
        ]:
            assert key in data, f"Missing key: {key}"

    def test_enrich_malicious_result(self, client, mock_aggregator):
        mock_aggregator.enrich_ioc.return_value = _enriched_result(
            reputation="MALICIOUS", score=85,
        )
        resp = client.post("/enrich", json={"indicator": "8.8.8.8", "ioc_type": "ip"})
        data = resp.json()
        assert data["reputation"] == "MALICIOUS"
        assert data["confidence_score"] == 85
        assert data["is_malicious"] is True

    def test_enrich_force_refresh_defaults_false(self, client, mock_aggregator):
        client.post("/enrich", json={"indicator": "8.8.8.8", "ioc_type": "ip"})
        mock_aggregator.enrich_ioc.assert_called_once_with(
            indicator="8.8.8.8", ioc_type="ip", force_refresh=False,
        )


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

class TestStats:
    @patch("api.routes.CacheManager")
    def test_stats_returns_200(self, mock_cm, client):
        mock_cm.stats = AsyncMock(return_value={
            "total_cached": 42,
            "expired": 3,
            "by_reputation": {"MALICIOUS": 5, "CLEAN": 37},
        })
        resp = client.get("/stats")
        assert resp.status_code == 200

    @patch("api.routes.CacheManager")
    def test_stats_has_expected_fields(self, mock_cm, client):
        mock_cm.stats = AsyncMock(return_value={
            "total_cached": 100,
            "expired": 10,
            "by_reputation": {"MALICIOUS": 20, "SUSPICIOUS": 10, "CLEAN": 70},
        })
        data = client.get("/stats").json()
        assert data["total_iocs"] == 100
        assert "iocs_by_reputation" in data
        assert data["iocs_by_reputation"]["MALICIOUS"] == 20
        assert "timestamp" in data

    @patch("api.routes.CacheManager")
    def test_stats_handles_db_failure(self, mock_cm, client):
        mock_cm.stats = AsyncMock(side_effect=Exception("db down"))
        resp = client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_iocs"] == 0
