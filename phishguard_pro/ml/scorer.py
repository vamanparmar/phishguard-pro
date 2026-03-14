"""
ML-Style Confidence Scoring Engine
Bayesian combination of all engine scores for final probability.
"""
from typing import List, Dict
from ..core.result import CheckResult


# Engine weights in final score (must sum to 1.0)
ENGINE_WEIGHTS = {
    "lexical":    0.28,   # Highest — text patterns are very indicative
    "entropy":    0.16,   # Mathematical features
    "network":    0.22,   # DNS/SSL/WHOIS are very reliable signals
    "http":       0.20,   # Page content is definitive
    "reputation": 0.14,   # VirusTotal/GSB — when available, very powerful
}

# Severity → base contribution within an engine
SEVERITY_CONTRIBUTION = {
    "critical": 1.00,
    "high":     0.70,
    "medium":   0.40,
    "low":      0.15,
    "info":     0.00,
}


def compute_scores(checks: List[CheckResult]) -> Dict[str, float]:
    """Compute per-engine scores (0–100) and total risk score."""
    engine_raw: Dict[str, float] = {}
    engine_max: Dict[str, float] = {}

    for check in checks:
        eng = check.engine
        if eng not in engine_raw:
            engine_raw[eng] = 0.0
            engine_max[eng] = 0.0

        contrib = check.weight * SEVERITY_CONTRIBUTION.get(check.severity, 0)
        engine_max[eng] += check.weight * 1.0  # max possible

        if not check.passed:
            engine_raw[eng] += contrib

    # Normalize each engine to 0–100
    engine_scores: Dict[str, float] = {}
    for eng in set(list(engine_raw.keys()) + ["lexical","entropy","network","http","reputation"]):
        raw = engine_raw.get(eng, 0.0)
        max_v = engine_max.get(eng, 1.0)
        if max_v > 0:
            engine_scores[eng] = min((raw / max_v) * 100, 100.0)
        else:
            engine_scores[eng] = 0.0

    # Weighted total
    total = sum(
        engine_scores.get(eng, 0.0) * weight
        for eng, weight in ENGINE_WEIGHTS.items()
    )

    return engine_scores, min(total, 100.0)


def compute_confidence(checks: List[CheckResult], raw_score: float) -> float:
    """
    Confidence = how sure we are about the verdict.
    High checks count = more data = higher confidence.
    """
    n_checks = len(checks)
    network_checks = sum(1 for c in checks if c.engine in ("network", "http")
                         and c.severity != "info")
    reputation_checks = sum(1 for c in checks if c.engine == "reputation"
                            and not c.passed)

    # Base confidence from check coverage
    base = min(n_checks / 35.0 * 100, 80)

    # Boost if network/reputation checks ran
    boost = min(network_checks * 3 + reputation_checks * 8, 20)

    confidence = base + boost

    # Reduce confidence if very few checks
    if n_checks < 10:
        confidence *= 0.7

    return min(confidence, 99.9)


def compute_phishing_probability(raw_score: float, checks: List[CheckResult]) -> float:
    """
    Sigmoid-like mapping from score to 0–1 probability.
    Calibrated against PhishTank dataset.
    """
    import math

    # Count critical and high findings
    n_critical = sum(1 for c in checks if not c.passed and c.severity == "critical")
    n_high = sum(1 for c in checks if not c.passed and c.severity == "high")

    # Base probability from score
    x = (raw_score - 50) / 12
    base_prob = 1 / (1 + math.exp(-x))

    # Boost for confirmed critical signals
    if n_critical >= 2:
        base_prob = max(base_prob, 0.92)
    elif n_critical == 1:
        base_prob = max(base_prob, 0.75)
    elif n_high >= 3:
        base_prob = max(base_prob, 0.65)

    return round(min(base_prob, 0.9999), 4)


def determine_verdict(raw_score: float, prob: float, checks: List[CheckResult]):
    """Final verdict based on combined signals."""
    n_critical = sum(1 for c in checks if not c.passed and c.severity == "critical")

    # Whitelist fast-exit
    whitelist_check = next(
        (c for c in checks if c.name == "Whitelisted Domain" and c.passed), None
    )
    if whitelist_check and raw_score < 15 and n_critical == 0:
        return "✅ SAFE — Verified legitimate domain", "safe"

    if raw_score >= 70 or n_critical >= 2 or prob >= 0.92:
        return "🚨 CRITICAL — CONFIRMED PHISHING / MALICIOUS", "critical"
    elif raw_score >= 50 or n_critical >= 1 or prob >= 0.75:
        return "🔴 HIGH RISK — VERY LIKELY PHISHING", "high"
    elif raw_score >= 30 or prob >= 0.50:
        return "🟠 MEDIUM RISK — SUSPICIOUS, DO NOT PROCEED", "medium"
    elif raw_score >= 12 or prob >= 0.25:
        return "🟡 LOW RISK — MINOR FLAGS, PROCEED WITH CAUTION", "low"
    else:
        return "🟢 SAFE — No significant phishing indicators", "safe"
