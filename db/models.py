import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from core.config import settings

logger = logging.getLogger(__name__)

DB_PATH = settings.database_path

CREATE_IOCS_TABLE = """
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('ip', 'domain', 'hash', 'url')),
    reputation TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK(reputation IN ('MALICIOUS', 'SUSPICIOUS', 'SCANNER', 'CLEAN', 'UNKNOWN')),
    confidence_score INTEGER NOT NULL DEFAULT 0 CHECK(confidence_score BETWEEN 0 AND 100),
    sources TEXT NOT NULL DEFAULT '[]',
    metadata TEXT NOT NULL DEFAULT '{}',
    first_seen TIMESTAMP NOT NULL,
    last_updated TIMESTAMP NOT NULL,
    ttl TIMESTAMP NOT NULL
);
"""

CREATE_RATE_LIMITS_TABLE = """
CREATE TABLE IF NOT EXISTS rate_limits (
    source TEXT PRIMARY KEY,
    requests_today INTEGER NOT NULL DEFAULT 0,
    daily_limit INTEGER NOT NULL,
    last_reset TIMESTAMP NOT NULL
);
"""

CREATE_INDICATOR_INDEX = """
CREATE INDEX IF NOT EXISTS idx_iocs_indicator ON iocs(indicator);
"""

CREATE_TTL_INDEX = """
CREATE INDEX IF NOT EXISTS idx_iocs_ttl ON iocs(ttl);
"""


async def init_db() -> None:
    """Initialize the database schema and ensure the data directory exists."""
    db_path = Path(DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_IOCS_TABLE)
        await db.execute(CREATE_RATE_LIMITS_TABLE)
        await db.execute(CREATE_INDICATOR_INDEX)
        await db.execute(CREATE_TTL_INDEX)
        await db.commit()

    logger.info("Database initialized at %s", DB_PATH)


async def get_db() -> aiosqlite.Connection:
    """Return a new database connection with row factory enabled."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


class IOCRecord:
    """Represents a cached IOC enrichment record."""

    def __init__(
        self,
        indicator: str,
        ioc_type: str,
        reputation: str = "UNKNOWN",
        confidence_score: int = 0,
        sources: list[str] | None = None,
        metadata: dict | None = None,
        first_seen: datetime | None = None,
        last_updated: datetime | None = None,
        ttl: datetime | None = None,
    ):
        now = datetime.now(timezone.utc)
        self.indicator = indicator
        self.type = ioc_type
        self.reputation = reputation
        self.confidence_score = confidence_score
        self.sources = sources or []
        self.metadata = metadata or {}
        self.first_seen = first_seen or now
        self.last_updated = last_updated or now
        self.ttl = ttl or now

    def to_dict(self) -> dict:
        """Serialize the record to a dictionary."""
        return {
            "indicator": self.indicator,
            "type": self.type,
            "reputation": self.reputation,
            "confidence_score": self.confidence_score,
            "sources": self.sources,
            "metadata": self.metadata,
            "first_seen": self.first_seen.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "ttl": self.ttl.isoformat(),
        }

    @classmethod
    def from_row(cls, row: aiosqlite.Row) -> "IOCRecord":
        """Construct an IOCRecord from a database row."""
        return cls(
            indicator=row["indicator"],
            ioc_type=row["type"],
            reputation=row["reputation"],
            confidence_score=row["confidence_score"],
            sources=json.loads(row["sources"]),
            metadata=json.loads(row["metadata"]),
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_updated=datetime.fromisoformat(row["last_updated"]),
            ttl=datetime.fromisoformat(row["ttl"]),
        )


class RateLimitTracker:
    """Tracks daily API request counts per source."""

    @staticmethod
    async def init_source(db: aiosqlite.Connection, source: str, daily_limit: int) -> None:
        """Register a source with its daily rate limit."""
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """INSERT OR IGNORE INTO rate_limits (source, requests_today, daily_limit, last_reset)
               VALUES (?, 0, ?, ?)""",
            (source, daily_limit, now),
        )
        await db.commit()

    @staticmethod
    async def can_request(db: aiosqlite.Connection, source: str) -> bool:
        """Check if the source has remaining quota for today."""
        row = await db.execute_fetchall(
            "SELECT requests_today, daily_limit, last_reset FROM rate_limits WHERE source = ?",
            (source,),
        )
        if not row:
            return True

        requests_today, daily_limit, last_reset = row[0]
        last_reset_dt = datetime.fromisoformat(last_reset)
        now = datetime.now(timezone.utc)

        # Reset counter if a new day has started
        if now.date() > last_reset_dt.date():
            await db.execute(
                "UPDATE rate_limits SET requests_today = 0, last_reset = ? WHERE source = ?",
                (now.isoformat(), source),
            )
            await db.commit()
            return True

        return requests_today < daily_limit

    @staticmethod
    async def increment(db: aiosqlite.Connection, source: str) -> None:
        """Record one API request for the source."""
        await db.execute(
            "UPDATE rate_limits SET requests_today = requests_today + 1 WHERE source = ?",
            (source,),
        )
        await db.commit()

    @staticmethod
    async def get_remaining(db: aiosqlite.Connection, source: str) -> int | None:
        """Return remaining requests for today, or None if source is untracked."""
        row = await db.execute_fetchall(
            "SELECT requests_today, daily_limit FROM rate_limits WHERE source = ?",
            (source,),
        )
        if not row:
            return None
        return row[0][1] - row[0][0]
