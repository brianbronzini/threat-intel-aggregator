import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import aiosqlite

from core.config import settings
from db.models import DB_PATH, IOCRecord

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _connect():
    """Open a DB connection with busy timeout for concurrent access."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA busy_timeout=5000")
        yield db


class CacheManager:
    """Manages IOC caching with configurable TTL per IOC type."""

    @staticmethod
    async def get(indicator: str) -> IOCRecord | None:
        """Retrieve a cached IOC if it exists and hasn't expired."""
        async with _connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM iocs WHERE indicator = ?", (indicator,)
            )
            row = await cursor.fetchone()

            if row is None:
                logger.debug("Cache miss: %s", indicator)
                return None

            record = IOCRecord.from_row(row)
            now = datetime.now(timezone.utc)

            if now > record.ttl:
                logger.debug("Cache expired: %s (ttl=%s)", indicator, record.ttl)
                return None

            logger.debug("Cache hit: %s", indicator)
            return record

    @staticmethod
    async def store(record: IOCRecord) -> None:
        """Insert or update a cached IOC record with a fresh TTL."""
        ttl_hours = settings.get_cache_ttl_hours(record.type)
        record.ttl = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
        record.last_updated = datetime.now(timezone.utc)

        async with _connect() as db:
            await db.execute(
                """INSERT INTO iocs
                   (indicator, type, reputation, confidence_score, sources, metadata,
                    first_seen, last_updated, ttl)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(indicator) DO UPDATE SET
                       reputation = excluded.reputation,
                       confidence_score = excluded.confidence_score,
                       sources = excluded.sources,
                       metadata = excluded.metadata,
                       last_updated = excluded.last_updated,
                       ttl = excluded.ttl
                """,
                (
                    record.indicator,
                    record.type,
                    record.reputation,
                    record.confidence_score,
                    json.dumps(record.sources),
                    json.dumps(record.metadata),
                    record.first_seen.isoformat(),
                    record.last_updated.isoformat(),
                    record.ttl.isoformat(),
                ),
            )
            await db.commit()

        logger.info(
            "Cached IOC: %s [%s] score=%d ttl=%dh",
            record.indicator,
            record.reputation,
            record.confidence_score,
            ttl_hours,
        )

    @staticmethod
    async def delete(indicator: str) -> bool:
        """Remove an IOC from the cache. Returns True if a row was deleted."""
        async with _connect() as db:
            cursor = await db.execute(
                "DELETE FROM iocs WHERE indicator = ?", (indicator,)
            )
            await db.commit()
            return cursor.rowcount > 0

    @staticmethod
    async def purge_expired() -> int:
        """Delete all IOCs past their TTL. Returns the count of removed records."""
        now = datetime.now(timezone.utc).isoformat()
        async with _connect() as db:
            cursor = await db.execute("DELETE FROM iocs WHERE ttl < ?", (now,))
            await db.commit()
            count = cursor.rowcount
            if count:
                logger.info("Purged %d expired IOC records", count)
            return count

    @staticmethod
    async def stats() -> dict:
        """Return basic cache statistics."""
        async with _connect() as db:
            total = await db.execute_fetchall("SELECT COUNT(*) FROM iocs")
            now = datetime.now(timezone.utc).isoformat()
            expired = await db.execute_fetchall(
                "SELECT COUNT(*) FROM iocs WHERE ttl < ?", (now,)
            )
            by_reputation = await db.execute_fetchall(
                "SELECT reputation, COUNT(*) FROM iocs GROUP BY reputation"
            )
            return {
                "total_cached": total[0][0],
                "expired": expired[0][0],
                "by_reputation": {row[0]: row[1] for row in by_reputation},
            }
