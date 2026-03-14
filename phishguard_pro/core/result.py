"""
ScanResult — Full structured output with confidence scoring
"""
from dataclasses import dataclass, field
from typing import List, Any, Optional
import json


@dataclass
class CheckResult:
    name: str
    engine: str           # structural|lexical|entropy|reputation|network|http|ml
    severity: str         # critical|high|medium|low|info
    passed: bool
    weight: float         # 0.0–1.0 contribution to final confidence
    detail: str
    evidence: Any = None

    def to_dict(self):
        return {
            "name": self.name,
            "engine": self.engine,
            "severity": self.severity,
            "passed": self.passed,
            "weight": self.weight,
            "detail": self.detail,
            "evidence": str(self.evidence)[:200] if self.evidence else None,
        }


@dataclass
class ScanResult:
    url: str
    normalized_url: str
    domain: str
    registered_domain: str
    tld: str
    subdomain: str
    timestamp: str

    checks: List[CheckResult] = field(default_factory=list)

    # Scoring
    raw_score: float = 0.0          # 0–100 weighted
    confidence: float = 0.0         # 0–100% how sure we are
    phishing_probability: float = 0.0  # 0–1.0
    verdict: str = ""
    verdict_level: str = ""         # safe|low|medium|high|critical
    summary: List[str] = field(default_factory=list)

    # Sub-scores by engine
    structural_score: float = 0.0
    lexical_score: float = 0.0
    entropy_score: float = 0.0
    reputation_score: float = 0.0
    network_score: float = 0.0
    http_score: float = 0.0

    # Metadata
    virustotal_positives: Optional[int] = None
    virustotal_total: Optional[int] = None
    whois_age_days: Optional[int] = None
    resolved_ip: Optional[str] = None
    ssl_valid: Optional[bool] = None
    final_url: Optional[str] = None

    def to_dict(self):
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "registered_domain": self.registered_domain,
            "tld": self.tld,
            "subdomain": self.subdomain,
            "timestamp": self.timestamp,
            "scores": {
                "raw_score": round(self.raw_score, 2),
                "confidence": round(self.confidence, 2),
                "phishing_probability": round(self.phishing_probability, 4),
                "structural": round(self.structural_score, 2),
                "lexical": round(self.lexical_score, 2),
                "entropy": round(self.entropy_score, 2),
                "reputation": round(self.reputation_score, 2),
                "network": round(self.network_score, 2),
                "http": round(self.http_score, 2),
            },
            "verdict": self.verdict,
            "verdict_level": self.verdict_level,
            "summary": self.summary,
            "metadata": {
                "virustotal_positives": self.virustotal_positives,
                "virustotal_total": self.virustotal_total,
                "whois_age_days": self.whois_age_days,
                "resolved_ip": self.resolved_ip,
                "ssl_valid": self.ssl_valid,
                "final_url": self.final_url,
            },
            "checks": [c.to_dict() for c in self.checks],
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @property
    def failed_checks(self):
        return [c for c in self.checks if not c.passed]

    @property
    def critical_findings(self):
        return [c for c in self.checks if not c.passed and c.severity == "critical"]

    @property
    def is_phishing(self):
        return self.verdict_level in ("high", "critical")
