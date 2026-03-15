from datetime import datetime

import pytest
import aiosqlite

from db.models import IOCRecord, RateLimitTracker, init_db, DB_PATH
from db.cache import CacheManager
from sources.base import ThreatIntelSource


# Use a temporary database for tests so we don't touch the real one
@pytest.fixture(autouse=True)
def tmp_db(monkeypatch, tmp_path):
    test_db = str(tmp_path / "test_cache.db")
    monkeypatch.setattr("db.models.DB_PATH", test_db)
    monkeypatch.setattr("db.cache.DB_PATH", test_db)


# -- Database initialization --------------------------------------------------


@pytest.mark.asyncio
async def test_init_db_creates_tables(tmp_path, monkeypatch):
    db_path = str(tmp_path / "fresh.db")
    monkeypatch.setattr("db.models.DB_PATH", db_path)

    await init_db()

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in await cursor.fetchall()]

    assert "iocs" in tables
    assert "rate_limits" in tables


@pytest.mark.asyncio
async def test_init_db_is_idempotent(tmp_path, monkeypatch):
    db_path = str(tmp_path / "idem.db")
    monkeypatch.setattr("db.models.DB_PATH", db_path)

    await init_db()
    await init_db()  # should not raise


# -- IOCRecord model ----------------------------------------------------------


def test_ioc_record_defaults():
    record = IOCRecord(indicator="8.8.8.8", ioc_type="ip")

    assert record.indicator == "8.8.8.8"
    assert record.type == "ip"
    assert record.reputation == "UNKNOWN"
    assert record.confidence_score == 0
    assert record.sources == []
    assert record.metadata == {}
    assert isinstance(record.first_seen, datetime)


def test_ioc_record_to_dict():
    record = IOCRecord(
        indicator="evil.com",
        ioc_type="domain",
        reputation="MALICIOUS",
        confidence_score=85,
        sources=["greynoise", "abuseipdb"],
    )
    data = record.to_dict()

    assert data["indicator"] == "evil.com"
    assert data["type"] == "domain"
    assert data["reputation"] == "MALICIOUS"
    assert data["confidence_score"] == 85
    assert data["sources"] == ["greynoise", "abuseipdb"]


# -- Cache insert and retrieve ------------------------------------------------


@pytest.mark.asyncio
async def test_cache_store_and_get():
    await init_db()

    record = IOCRecord(
        indicator="192.168.1.1",
        ioc_type="ip",
        reputation="SUSPICIOUS",
        confidence_score=45,
        sources=["greynoise"],
        metadata={"classification": "malicious"},
    )
    await CacheManager.store(record)

    cached = await CacheManager.get("192.168.1.1")
    assert cached is not None
    assert cached.indicator == "192.168.1.1"
    assert cached.reputation == "SUSPICIOUS"
    assert cached.confidence_score == 45
    assert cached.sources == ["greynoise"]
    assert cached.metadata == {"classification": "malicious"}


@pytest.mark.asyncio
async def test_cache_miss_returns_none():
    await init_db()

    result = await CacheManager.get("10.0.0.1")
    assert result is None


@pytest.mark.asyncio
async def test_cache_update_existing():
    await init_db()

    record = IOCRecord(indicator="1.2.3.4", ioc_type="ip", confidence_score=20)
    await CacheManager.store(record)

    record.confidence_score = 80
    record.reputation = "MALICIOUS"
    await CacheManager.store(record)

    cached = await CacheManager.get("1.2.3.4")
    assert cached.confidence_score == 80
    assert cached.reputation == "MALICIOUS"


@pytest.mark.asyncio
async def test_cache_delete():
    await init_db()

    record = IOCRecord(indicator="5.6.7.8", ioc_type="ip")
    await CacheManager.store(record)

    deleted = await CacheManager.delete("5.6.7.8")
    assert deleted is True

    assert await CacheManager.get("5.6.7.8") is None


@pytest.mark.asyncio
async def test_cache_stats():
    await init_db()

    await CacheManager.store(
        IOCRecord(indicator="1.1.1.1", ioc_type="ip", reputation="CLEAN")
    )
    await CacheManager.store(
        IOCRecord(indicator="2.2.2.2", ioc_type="ip", reputation="MALICIOUS")
    )

    stats = await CacheManager.stats()
    assert stats["total_cached"] == 2
    assert "CLEAN" in stats["by_reputation"]
    assert "MALICIOUS" in stats["by_reputation"]


# -- Rate limit tracker -------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limit_tracker():
    await init_db()

    db_path = DB_PATH  # already monkeypatched
    async with aiosqlite.connect(db_path) as db:
        # workaround: init_db used the monkeypatched path, but we need
        # to re-read it since monkeypatch changed the module-level var
        pass

    from db.models import DB_PATH as current_path

    async with aiosqlite.connect(current_path) as db:
        db.row_factory = aiosqlite.Row
        await RateLimitTracker.init_source(db, "test_source", 2)

        assert await RateLimitTracker.can_request(db, "test_source") is True

        await RateLimitTracker.increment(db, "test_source")
        await RateLimitTracker.increment(db, "test_source")

        assert await RateLimitTracker.can_request(db, "test_source") is False

        remaining = await RateLimitTracker.get_remaining(db, "test_source")
        assert remaining == 0


# -- Base API client -----------------------------------------------------------


class DummySource(ThreatIntelSource):
    """Concrete subclass for testing the abstract base."""

    source_name = "dummy"
    base_url = "https://example.com"
    daily_limit = 0

    async def lookup(self, indicator: str, ioc_type: str) -> dict | None:
        return {"source": self.source_name, "indicator": indicator}


def test_base_client_instantiation():
    client = DummySource(api_key="test-key-123")

    assert client.api_key == "test-key-123"
    assert client.source_name == "dummy"
    assert client.is_configured is True
    assert client._session is None


@pytest.mark.asyncio
async def test_base_client_session_lifecycle():
    client = DummySource()

    session = await client._get_session()
    assert session is not None
    assert not session.closed

    await client.close()
    assert client._session is None


@pytest.mark.asyncio
async def test_dummy_lookup():
    client = DummySource()
    result = await client.lookup("8.8.8.8", "ip")

    assert result == {"source": "dummy", "indicator": "8.8.8.8"}
    await client.close()
