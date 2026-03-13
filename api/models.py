from pydantic import BaseModel, Field


class IOCRequest(BaseModel):
    """Request to enrich a single IOC."""
    indicator: str = Field(..., description="The IOC value (IP, domain, hash, or URL)")
    ioc_type: str = Field(
        ..., pattern="^(ip|domain|hash|url)$",
        description="Type of IOC: ip, domain, hash, or url",
    )
    force_refresh: bool = Field(
        False, description="Bypass cache and query sources directly",
    )


class IOCResponse(BaseModel):
    """Enrichment result for a single IOC."""
    indicator: str
    ioc_type: str
    reputation: str
    confidence_score: int
    sources: list[str]
    metadata: dict
    cached: bool = False


class BulkIOCRequest(BaseModel):
    """Request to enrich multiple IOCs."""
    indicators: list[IOCRequest] = Field(
        ..., min_length=1, max_length=100,
        description="List of IOCs to enrich (max 100)",
    )


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    cache_stats: dict | None = None
