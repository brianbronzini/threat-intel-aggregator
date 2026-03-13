"""Tests for the ThreatIntelAggregator enrichment engine."""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.aggregator import ThreatIntelAggregator
from db.models import IOCRecord


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

def _make_source(name: str, result: dict | None = None, delay: float = 0):
    """Create a mock source client that returns `result` after `delay` seconds."""
    source = AsyncMock()
    source.source_name = name

    async def _lookup(indicator, ioc_type):
        if delay:
            await asyncio.sleep(delay)
        return result

    source.lookup = AsyncMock(side_effect=_lookup)
    source.close = AsyncMock()
    return source


def _greynoise_result(is_noise=False, is_malicious=False):
    return {"source": "greynoise", "is_noise": is_noise, "is_malicious": is_malicious}


def _abuseipdb_result(confidence_score=0):
    return {"source": "abuseipdb", "confidence_score": confidence_score}


def _virustotal_result(positives=0):
    return {"source": "virustotal", "positives": positives, "is_malicious": positives > 5}


def _ipinfo_result():
    return {
        "source": "ipinfo",
        "is_malicious": False,
        "country": "US",
        "country_code": "US",
        "city": "Mountain View",
        "region": "California",
        "org": "Google LLC",
        "asn": "AS15169",
        "latitude": "37.386",
        "longitude": "-122.084",
        "timezone": "America/Los_Angeles",
    }


def _threatfox_result(max_confidence=80):
    return {
        "source": "threatfox",
        "is_malicious": max_confidence >= 50,
        "max_confidence": max_confidence,
        "threat_types": ["botnet_cc"],
        "malware_families": ["Emotet"],
        "tags": ["emotet", "epoch5"],
    }


def _urlhaus_result(is_malicious=True):
    return {
        "source": "urlhaus",
        "is_malicious": is_malicious,
        "tags": ["elf", "mirai"],
    }


def _mock_cache(hit: IOCRecord | None = None, store_raises=False):
    cache = MagicMock()
    cache.get = AsyncMock(return_value=hit)
    if store_raises:
        cache.store = AsyncMock(side_effect=Exception("db write failed"))
    else:
        cache.store = AsyncMock()
    return cache


def _ip_sources(**overrides):
    """Return a dict of mock sources for an IP lookup."""
    defaults = {
        "greynoise": _make_source("greynoise", _greynoise_result()),
        "abuseipdb": _make_source("abuseipdb", _abuseipdb_result()),
        "virustotal": _make_source("virustotal", _virustotal_result()),
        "threatfox": _make_source("threatfox", _threatfox_result(max_confidence=10)),
        "ipinfo": _make_source("ipinfo", _ipinfo_result()),
        "urlhaus": _make_source("urlhaus", _urlhaus_result(is_malicious=False)),
    }
    defaults.update(overrides)
    return defaults


IP = "8.8.8.8"
DOMAIN = "evil.example.com"
URL = "https://evil.example.com/payload.exe"
HASH_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
HASH_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidation:
    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.2.3.4", "255.255.255.255"])
    async def test_valid_ipv4(self, ip):
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=_ip_sources())
        result = await agg.enrich_ioc(ip, "ip")
        assert result["indicator"] == ip

    @pytest.mark.parametrize("ip", ["2001:4860:4860::8888", "::1", "fe80::1"])
    async def test_valid_ipv6(self, ip):
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=_ip_sources())
        result = await agg.enrich_ioc(ip, "ip")
        assert result["indicator"] == ip

    @pytest.mark.parametrize("ip", ["999.999.999.999", "not-an-ip", "1.2.3", ""])
    async def test_invalid_ip_rejected(self, ip):
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=_ip_sources())
        with pytest.raises(ValueError, match="Invalid ip"):
            await agg.enrich_ioc(ip, "ip")

    async def test_valid_domain(self):
        sources = {"threatfox": _make_source("threatfox", _threatfox_result(10))}
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(DOMAIN, "domain")
        assert result["type"] == "domain"

    @pytest.mark.parametrize("domain", ["no-tld", "-start.com", "has space.com", ""])
    async def test_invalid_domain_rejected(self, domain):
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources={})
        with pytest.raises(ValueError, match="Invalid domain"):
            await agg.enrich_ioc(domain, "domain")

    async def test_valid_url(self):
        sources = {
            "urlhaus": _make_source("urlhaus", _urlhaus_result(False)),
            "threatfox": _make_source("threatfox", _threatfox_result(10)),
        }
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(URL, "url")
        assert result["type"] == "url"

    @pytest.mark.parametrize("url", ["ftp://bad.com/f", "not-a-url", "://missing.com"])
    async def test_invalid_url_rejected(self, url):
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources={})
        with pytest.raises(ValueError, match="Invalid url"):
            await agg.enrich_ioc(url, "url")

    async def test_valid_md5_hash(self):
        sources = {
            "virustotal": _make_source("virustotal", _virustotal_result()),
            "threatfox": _make_source("threatfox", _threatfox_result(10)),
        }
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(HASH_MD5, "hash")
        assert result["type"] == "hash"

    async def test_valid_sha256_hash(self):
        sources = {
            "virustotal": _make_source("virustotal", _virustotal_result()),
            "threatfox": _make_source("threatfox", _threatfox_result(10)),
        }
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(HASH_SHA256, "hash")
        assert result["type"] == "hash"

    @pytest.mark.parametrize("h", ["abc", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "123"])
    async def test_invalid_hash_rejected(self, h):
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources={})
        with pytest.raises(ValueError, match="Invalid hash"):
            await agg.enrich_ioc(h, "hash")

    async def test_unknown_ioc_type_rejected(self):
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources={})
        with pytest.raises(ValueError, match="Unknown IOC type"):
            await agg.enrich_ioc("foo", "email")


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------

class TestCacheBehavior:
    async def test_cache_hit_returns_immediately(self):
        cached_record = IOCRecord(
            indicator=IP,
            ioc_type="ip",
            reputation="MALICIOUS",
            confidence_score=70,
            sources=["greynoise", "abuseipdb"],
            metadata={
                "cached": False,
                "sources": {
                    "greynoise": _greynoise_result(is_malicious=True),
                    "abuseipdb": _abuseipdb_result(90),
                },
            },
        )
        cache = _mock_cache(hit=cached_record)
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=cache, sources=sources)

        result = await agg.enrich_ioc(IP, "ip")

        assert result["metadata"]["cached"] is True
        assert result["reputation"] == "MALICIOUS"
        assert result["confidence_score"] == 70
        assert result["is_malicious"] is True
        assert "greynoise" in result["sources_consulted"]
        assert "abuseipdb" in result["sources_flagged"]
        assert "score_breakdown" in result
        assert "first_seen" in result
        assert "last_updated" in result
        assert "ttl" in result
        # No source should have been called
        for s in sources.values():
            s.lookup.assert_not_called()

    async def test_cache_miss_queries_sources(self):
        cache = _mock_cache(hit=None)
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=cache, sources=sources)

        result = await agg.enrich_ioc(IP, "ip")

        assert result["metadata"]["cached"] is False
        sources["greynoise"].lookup.assert_called_once()
        sources["abuseipdb"].lookup.assert_called_once()
        cache.store.assert_called_once()

    async def test_force_refresh_bypasses_cache(self):
        cached_record = IOCRecord(
            indicator=IP, ioc_type="ip", reputation="CLEAN", confidence_score=0,
            metadata={"sources": {}},
        )
        cache = _mock_cache(hit=cached_record)
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=cache, sources=sources)

        result = await agg.enrich_ioc(IP, "ip", force_refresh=True)

        # Cache.get should NOT have been called
        cache.get.assert_not_called()
        assert result["metadata"]["cached"] is False
        sources["greynoise"].lookup.assert_called_once()

    async def test_cache_read_failure_falls_through(self):
        cache = MagicMock()
        cache.get = AsyncMock(side_effect=Exception("db read error"))
        cache.store = AsyncMock()
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=cache, sources=sources)

        result = await agg.enrich_ioc(IP, "ip")

        # Should still succeed via source queries
        assert result["metadata"]["cached"] is False
        sources["greynoise"].lookup.assert_called_once()


# ---------------------------------------------------------------------------
# IOC type routing
# ---------------------------------------------------------------------------

class TestIOCTypeRouting:
    async def test_ip_calls_five_sources(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        await agg.enrich_ioc(IP, "ip")
        for name in ["greynoise", "abuseipdb", "virustotal", "threatfox", "ipinfo"]:
            sources[name].lookup.assert_called_once()
        sources["urlhaus"].lookup.assert_not_called()

    async def test_domain_calls_threatfox_only(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        await agg.enrich_ioc(DOMAIN, "domain")
        sources["threatfox"].lookup.assert_called_once()
        for name in ["greynoise", "abuseipdb", "virustotal", "urlhaus", "ipinfo"]:
            sources[name].lookup.assert_not_called()

    async def test_url_calls_urlhaus_and_threatfox(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        await agg.enrich_ioc(URL, "url")
        sources["urlhaus"].lookup.assert_called_once()
        sources["threatfox"].lookup.assert_called_once()
        sources["greynoise"].lookup.assert_not_called()

    async def test_hash_calls_virustotal_and_threatfox(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        await agg.enrich_ioc(HASH_MD5, "hash")
        sources["virustotal"].lookup.assert_called_once()
        sources["threatfox"].lookup.assert_called_once()
        sources["greynoise"].lookup.assert_not_called()


# ---------------------------------------------------------------------------
# Parallel execution
# ---------------------------------------------------------------------------

class TestParallelExecution:
    async def test_sources_run_in_parallel(self):
        """Total time should be ~max(delays), not sum(delays)."""
        sources = {
            "greynoise": _make_source("greynoise", _greynoise_result(), delay=0.1),
            "abuseipdb": _make_source("abuseipdb", _abuseipdb_result(), delay=0.1),
            "virustotal": _make_source("virustotal", _virustotal_result(), delay=0.1),
            "threatfox": _make_source("threatfox", _threatfox_result(10), delay=0.1),
            "ipinfo": _make_source("ipinfo", _ipinfo_result(), delay=0.1),
        }
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)

        start = time.monotonic()
        await agg.enrich_ioc(IP, "ip")
        elapsed = time.monotonic() - start

        # Sequential would be ~0.5s; parallel should be ~0.1s
        assert elapsed < 0.35, f"Took {elapsed:.2f}s — sources are not parallel"


# ---------------------------------------------------------------------------
# Error scenarios
# ---------------------------------------------------------------------------

class TestErrorScenarios:
    async def test_one_source_fails_others_succeed(self):
        failing = AsyncMock()
        failing.lookup = AsyncMock(side_effect=Exception("timeout"))
        failing.close = AsyncMock()

        sources = _ip_sources(greynoise=failing)
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        # greynoise should be None in metadata
        assert result["metadata"]["sources"]["greynoise"] is None
        # Other sources should still be present
        assert result["metadata"]["sources"]["abuseipdb"] is not None

    async def test_all_sources_fail(self):
        failing = AsyncMock()
        failing.lookup = AsyncMock(side_effect=Exception("fail"))
        failing.close = AsyncMock()

        sources = {name: failing for name in ["greynoise", "abuseipdb", "virustotal", "threatfox", "ipinfo"]}
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        assert result["reputation"] == "CLEAN"
        assert result["confidence_score"] == 0

    async def test_cache_store_failure_still_returns_result(self):
        cache = _mock_cache(store_raises=True)
        sources = _ip_sources(
            abuseipdb=_make_source("abuseipdb", _abuseipdb_result(90))
        )
        agg = ThreatIntelAggregator(cache=cache, sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        # Should still return enriched result despite cache failure
        assert result["indicator"] == IP
        assert result["score_breakdown"]["abuseipdb_points"] == 40


# ---------------------------------------------------------------------------
# Data aggregation
# ---------------------------------------------------------------------------

class TestDataAggregation:
    async def test_ipinfo_enrichment_included(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        assert result["enrichment"]["country"] == "US"
        assert result["enrichment"]["city"] == "Mountain View"
        assert result["enrichment"]["org"] == "Google LLC"
        assert result["enrichment"]["asn"] == "AS15169"

    async def test_threatfox_threat_details(self):
        sources = _ip_sources(
            threatfox=_make_source("threatfox", _threatfox_result(80))
        )
        agg = ThreatIntelAggregator(cache=cache if (cache := _mock_cache()) else cache, sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        assert "botnet_cc" in result["threat_details"]["threat_types"]
        assert "Emotet" in result["threat_details"]["malware_families"]
        assert "emotet" in result["threat_details"]["tags"]

    async def test_urlhaus_tags_included(self):
        sources = {
            "urlhaus": _make_source("urlhaus", _urlhaus_result(True)),
            "threatfox": _make_source("threatfox", _threatfox_result(10)),
        }
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(URL, "url")

        assert "elf" in result["threat_details"]["tags"]
        assert "mirai" in result["threat_details"]["tags"]

    async def test_metadata_includes_source_responses(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        meta_sources = result["metadata"]["sources"]
        assert "greynoise" in meta_sources
        assert "abuseipdb" in meta_sources
        assert meta_sources["greynoise"]["source"] == "greynoise"

    async def test_is_malicious_convenience_field(self):
        # MALICIOUS
        sources = _ip_sources(
            abuseipdb=_make_source("abuseipdb", _abuseipdb_result(90)),
            greynoise=_make_source("greynoise", _greynoise_result(is_malicious=True)),
        )
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")
        assert result["is_malicious"] is True

    async def test_clean_is_not_malicious(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")
        assert result["is_malicious"] is False

    async def test_no_ipinfo_means_empty_enrichment(self):
        sources = _ip_sources(ipinfo=_make_source("ipinfo", None))
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")
        assert result["enrichment"] == {}


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

class TestResultStructure:
    async def test_all_top_level_keys_present(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        for key in [
            "indicator", "type", "reputation", "confidence_score",
            "is_malicious", "sources_consulted", "sources_flagged",
            "enrichment", "threat_details", "metadata", "score_breakdown",
            "first_seen", "last_updated", "ttl",
        ]:
            assert key in result, f"Missing key: {key}"

    async def test_metadata_keys(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")
        meta = result["metadata"]

        assert "cached" in meta
        assert "cache_age_seconds" in meta
        assert "query_time_ms" in meta
        assert "timestamp" in meta
        assert "sources" in meta

    async def test_query_time_ms_is_recorded(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")
        assert isinstance(result["metadata"]["query_time_ms"], int)
        assert result["metadata"]["query_time_ms"] >= 0


# ---------------------------------------------------------------------------
# Scoring integration
# ---------------------------------------------------------------------------

class TestScoringIntegration:
    async def test_malicious_ip_scored_correctly(self):
        sources = _ip_sources(
            greynoise=_make_source("greynoise", _greynoise_result(is_malicious=True)),
            abuseipdb=_make_source("abuseipdb", _abuseipdb_result(90)),
        )
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        assert result["reputation"] == "MALICIOUS"
        assert result["confidence_score"] == 70  # 30 + 40
        assert "greynoise" in result["sources_flagged"]
        assert "abuseipdb" in result["sources_flagged"]

    async def test_scanner_override(self):
        sources = _ip_sources(
            greynoise=_make_source("greynoise", _greynoise_result(is_noise=True)),
            abuseipdb=_make_source("abuseipdb", _abuseipdb_result(90)),
        )
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        assert result["reputation"] == "SCANNER"
        assert result["confidence_score"] == 20


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

class TestRobustness:
    async def test_whitespace_stripped_from_indicator(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc("  8.8.8.8  ", "ip")
        assert result["indicator"] == "8.8.8.8"

    async def test_newline_stripped_from_indicator(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        result = await agg.enrich_ioc("8.8.8.8\n", "ip")
        assert result["indicator"] == "8.8.8.8"

    async def test_score_above_100_capped_in_cache(self):
        """DB constrains confidence_score to 0-100, so cache store must cap it."""
        sources = _ip_sources(
            greynoise=_make_source("greynoise", _greynoise_result(is_malicious=True)),
            abuseipdb=_make_source("abuseipdb", _abuseipdb_result(90)),
            virustotal=_make_source("virustotal", _virustotal_result(10)),
            threatfox=_make_source("threatfox", _threatfox_result(80)),
            urlhaus=_make_source("urlhaus", _urlhaus_result(True)),
        )
        cache = _mock_cache()
        agg = ThreatIntelAggregator(cache=cache, sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        # Raw score exceeds 100
        assert result["confidence_score"] > 100
        assert result["reputation"] == "MALICIOUS"
        # But the value stored in cache is capped at 100
        stored_record = cache.store.call_args[0][0]
        assert stored_record.confidence_score == 100

    async def test_score_under_100_not_capped(self):
        sources = _ip_sources(
            abuseipdb=_make_source("abuseipdb", _abuseipdb_result(90)),
        )
        cache = _mock_cache()
        agg = ThreatIntelAggregator(cache=cache, sources=sources)
        result = await agg.enrich_ioc(IP, "ip")

        assert result["confidence_score"] == 40
        stored_record = cache.store.call_args[0][0]
        assert stored_record.confidence_score == 40


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------

class TestClose:
    async def test_close_closes_all_sources(self):
        sources = _ip_sources()
        agg = ThreatIntelAggregator(cache=_mock_cache(), sources=sources)
        await agg.close()
        for s in sources.values():
            s.close.assert_called_once()
