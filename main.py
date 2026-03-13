import logging

import uvicorn
from fastapi import FastAPI

from core.config import settings, setup_logging
from db.models import init_db

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Threat Intel Aggregator",
    description="Multi-source threat intelligence enrichment API",
    version="0.1.0",
)


@app.on_event("startup")
async def startup() -> None:
    setup_logging(settings.log_level)
    await init_db()
    logger.info("Threat Intel Aggregator started")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
