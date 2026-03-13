import logging
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # API Keys
    greynoise_api_key: str = ""
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    ipinfo_api_key: str = ""
    threatfox_api_key: str = ""

    # Application
    log_level: str = "INFO"
    database_path: str = "data/cache.db"

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Cache TTL in hours per IOC type
    cache_ttl_ip: int = 168  # 7 days
    cache_ttl_domain: int = 168
    cache_ttl_hash: int = 336  # 14 days (hashes don't change reputation often)
    cache_ttl_url: int = 24  # URLs change frequently

    # Rate limits (requests per day) per source
    rate_limit_abuseipdb: int = 1000
    rate_limit_virustotal: int = 500
    rate_limit_ipinfo: int = 1500  # ~50k/month

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }

    def validate_api_keys(self, logger: logging.Logger) -> None:
        """Log warnings for missing API keys at startup."""
        required = {
            "ABUSEIPDB_API_KEY": self.abuseipdb_api_key,
            "VIRUSTOTAL_API_KEY": self.virustotal_api_key,
            "IPINFO_API_KEY": self.ipinfo_api_key,
            "THREATFOX_API_KEY": self.threatfox_api_key,
        }
        optional = {
            "GREYNOISE_API_KEY": self.greynoise_api_key,
        }

        missing_required = [k for k, v in required.items() if not v]
        missing_optional = [k for k, v in optional.items() if not v]

        if missing_required:
            logger.warning(
                "Missing API keys (sources will be disabled): %s",
                ", ".join(missing_required),
            )
        if missing_optional:
            logger.info(
                "Optional API keys not set (will use free tier): %s",
                ", ".join(missing_optional),
            )
        if not missing_required and not missing_optional:
            logger.info("All API keys configured")

    def get_cache_ttl_hours(self, ioc_type: str) -> int:
        """Return cache TTL in hours for a given IOC type."""
        ttl_map = {
            "ip": self.cache_ttl_ip,
            "domain": self.cache_ttl_domain,
            "hash": self.cache_ttl_hash,
            "url": self.cache_ttl_url,
        }
        return ttl_map.get(ioc_type, self.cache_ttl_ip)


def setup_logging(level: str = "INFO") -> None:
    """Configure application-wide logging."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


settings = Settings()
