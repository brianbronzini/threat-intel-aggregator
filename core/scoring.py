"""Reputation scoring algorithm for threat intelligence aggregation."""


def calculate_reputation(source_results: dict[str, dict | None]) -> dict:
    """
    Calculate reputation score and classification from source results.

    Args:
        source_results: Dict mapping source name to its result dict (or None if failed/skipped)

    Returns:
        Dict with reputation, confidence_score, sources_consulted, sources_flagged,
        and score_breakdown.
    """
    sources_consulted = [
        name for name, result in source_results.items() if result is not None
    ]
    sources_flagged = []
    breakdown = {
        "greynoise_points": 0,
        "abuseipdb_points": 0,
        "virustotal_points": 0,
        "threatfox_points": 0,
        "urlhaus_points": 0,
        "total": 0,
    }

    # 1. GreyNoise — scanner override
    gn = source_results.get("greynoise")
    if gn is not None:
        if gn.get("is_noise"):
            breakdown["greynoise_points"] = 20
            breakdown["total"] = 20
            return {
                "reputation": "SCANNER",
                "confidence_score": 20,
                "sources_consulted": sources_consulted,
                "sources_flagged": ["greynoise"],
                "score_breakdown": breakdown,
            }
        if gn.get("is_malicious"):
            breakdown["greynoise_points"] = 30
            sources_flagged.append("greynoise")

    # 2. AbuseIPDB
    ab = source_results.get("abuseipdb")
    if ab is not None:
        cs = ab.get("confidence_score", 0)
        if cs > 75:
            breakdown["abuseipdb_points"] = 40
            sources_flagged.append("abuseipdb")
        elif cs > 50:
            breakdown["abuseipdb_points"] = 20
            sources_flagged.append("abuseipdb")

    # 3. VirusTotal
    vt = source_results.get("virustotal")
    if vt is not None:
        positives = vt.get("positives", 0)
        if positives > 5:
            breakdown["virustotal_points"] = 30
            sources_flagged.append("virustotal")
        elif positives > 2:
            breakdown["virustotal_points"] = 15
            sources_flagged.append("virustotal")

    # 4. ThreatFox
    tf = source_results.get("threatfox")
    if tf is not None:
        if tf.get("max_confidence", 0) >= 50:
            breakdown["threatfox_points"] = 25
            sources_flagged.append("threatfox")

    # 5. URLhaus
    uh = source_results.get("urlhaus")
    if uh is not None:
        if uh.get("is_malicious"):
            breakdown["urlhaus_points"] = 35
            sources_flagged.append("urlhaus")

    # Total and classify
    total = sum(
        v for k, v in breakdown.items() if k != "total"
    )
    breakdown["total"] = total

    if total >= 70:
        reputation = "MALICIOUS"
    elif total >= 40:
        reputation = "SUSPICIOUS"
    elif total >= 20:
        reputation = "SCANNER"
    else:
        reputation = "CLEAN"

    return {
        "reputation": reputation,
        "confidence_score": total,
        "sources_consulted": sources_consulted,
        "sources_flagged": sources_flagged,
        "score_breakdown": breakdown,
    }
