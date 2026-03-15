"""FastAPI route definitions for the threat intel aggregator API."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

from api.models import IOCRequest
from core.config import settings
from core.aggregator import ThreatIntelAggregator
from db.cache import CacheManager

logger = logging.getLogger(__name__)

router = APIRouter()

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(
    api_key: str | None = Security(_api_key_header),
) -> str:
    """Validate the API key if one is configured."""
    if not settings.api_key:
        return ""  # No key configured, allow all (dev mode)
    if not api_key or api_key != settings.api_key:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return api_key


# Module-level aggregator instance, created lazily
_aggregator: ThreatIntelAggregator | None = None


def get_aggregator() -> ThreatIntelAggregator:
    """Return the shared aggregator instance, creating it on first use."""
    global _aggregator
    if _aggregator is None:
        _aggregator = ThreatIntelAggregator()
    return _aggregator


def set_aggregator(agg: ThreatIntelAggregator | None) -> None:
    """Override the aggregator instance (used by tests)."""
    global _aggregator
    _aggregator = agg


@router.get("/health")
async def health() -> dict:
    """Simple health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/enrich", dependencies=[Depends(require_api_key)])
async def enrich(request: IOCRequest) -> dict:
    """Enrich an IOC with threat intelligence from all applicable sources."""
    aggregator = get_aggregator()
    try:
        result = await aggregator.enrich_ioc(
            indicator=request.indicator,
            ioc_type=request.ioc_type,
            force_refresh=request.force_refresh,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Enrichment failed for %s", request.indicator)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/stats", dependencies=[Depends(require_api_key)])
async def stats() -> dict:
    """Return cache and enrichment statistics."""
    try:
        cache_stats = await CacheManager.stats()
    except Exception:
        logger.warning("Failed to retrieve cache stats")
        cache_stats = {"total_cached": 0, "expired": 0, "by_reputation": {}}

    return {
        "total_iocs": cache_stats.get("total_cached", 0),
        "iocs_by_reputation": cache_stats.get("by_reputation", {}),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
