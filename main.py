import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import get_aggregator, router
from core.config import settings, setup_logging
from db.models import init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(settings.log_level)
    settings.validate_api_keys(logger)
    await init_db()
    logger.info(
        "Threat Intel Aggregator started on %s:%d",
        settings.api_host,
        settings.api_port,
    )
    yield
    # Shutdown: close all source HTTP sessions
    try:
        aggregator = get_aggregator()
        await aggregator.close()
        logger.info("Aggregator sessions closed")
    except Exception:
        logger.warning("Error closing aggregator sessions during shutdown")


app = FastAPI(
    title="Threat Intel Aggregator",
    description="Multi-source threat intelligence enrichment API",
    version="0.1.0",
    lifespan=lifespan,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

app.include_router(router)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
    )
