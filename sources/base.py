import logging
from abc import ABC, abstractmethod

import aiohttp

from db.models import RateLimitTracker, get_db

logger = logging.getLogger(__name__)

# Retry config
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = [1, 2, 4]


class ThreatIntelSource(ABC):
    """Base class for all threat intelligence API clients.

    Subclasses must define `source_name`, `base_url`, and implement `lookup()`.
    The base class provides HTTP session management, rate limit tracking,
    and retry logic with exponential backoff for transient failures.
    """

    source_name: str = ""
    base_url: str = ""
    daily_limit: int = 0  # 0 means unlimited

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Lazily create and return the HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=10,
                connect=3,
                sock_read=7,
            )
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _check_rate_limit(self) -> bool:
        """Return True if this source still has quota remaining."""
        if self.daily_limit == 0:
            return True
        db = await get_db()
        try:
            await RateLimitTracker.init_source(db, self.source_name, self.daily_limit)
            return await RateLimitTracker.can_request(db, self.source_name)
        finally:
            await db.close()

    async def _record_request(self) -> None:
        """Increment the request counter for this source."""
        if self.daily_limit == 0:
            return
        db = await get_db()
        try:
            await RateLimitTracker.increment(db, self.source_name)
        finally:
            await db.close()

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        json_body: dict | None = None,
        form_data: dict | None = None,
    ) -> dict | None:
        """Make an HTTP request with rate limiting and retry logic.

        Args:
            json_body: Send as JSON (Content-Type: application/json).
            form_data: Send as form-encoded (Content-Type: application/x-www-form-urlencoded).

        Returns the parsed JSON response, or None on unrecoverable failure.
        """
        if not await self._check_rate_limit():
            logger.warning(
                "Rate limit reached for %s, skipping request", self.source_name
            )
            return None

        session = await self._get_session()

        for attempt in range(MAX_RETRIES):
            try:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                    data=form_data,
                ) as resp:
                    await self._record_request()

                    if resp.status == 200:
                        return await resp.json()

                    if resp.status == 429:
                        wait = RETRY_BACKOFF_SECONDS[
                            min(attempt, len(RETRY_BACKOFF_SECONDS) - 1)
                        ]
                        logger.warning(
                            "%s returned 429, retrying in %ds (attempt %d/%d)",
                            self.source_name,
                            wait,
                            attempt + 1,
                            MAX_RETRIES,
                        )
                        import asyncio

                        await asyncio.sleep(wait)
                        continue

                    if resp.status >= 500:
                        wait = RETRY_BACKOFF_SECONDS[
                            min(attempt, len(RETRY_BACKOFF_SECONDS) - 1)
                        ]
                        logger.error(
                            "%s server error %d, retrying in %ds (attempt %d/%d)",
                            self.source_name,
                            resp.status,
                            wait,
                            attempt + 1,
                            MAX_RETRIES,
                        )
                        import asyncio

                        await asyncio.sleep(wait)
                        continue

                    # Client errors (400, 401, 403, etc.) -- don't retry
                    body = await resp.text()
                    logger.error(
                        "%s client error %d for %s: %s",
                        self.source_name,
                        resp.status,
                        url,
                        body[:200],
                    )
                    return None

            except aiohttp.ClientError as exc:
                wait = RETRY_BACKOFF_SECONDS[
                    min(attempt, len(RETRY_BACKOFF_SECONDS) - 1)
                ]
                logger.error(
                    "%s connection error: %s, retrying in %ds (attempt %d/%d)",
                    self.source_name,
                    exc,
                    wait,
                    attempt + 1,
                    MAX_RETRIES,
                )
                import asyncio

                await asyncio.sleep(wait)

        logger.error("%s failed after %d retries", self.source_name, MAX_RETRIES)
        return None

    @abstractmethod
    async def lookup(self, indicator: str, ioc_type: str) -> dict | None:
        """Query this source for enrichment data on the given indicator.

        Args:
            indicator: The IOC value (IP, domain, hash, or URL).
            ioc_type: One of 'ip', 'domain', 'hash', 'url'.

        Returns:
            A dict with source-specific enrichment data, or None on failure.
        """

    @property
    def is_configured(self) -> bool:
        """Return True if this source has a valid API key (or doesn't need one)."""
        return True
