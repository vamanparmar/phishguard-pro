"""
PhishGuard PRO — Master Analyzer
Orchestrates all 6 engines and produces a final ScanResult.
"""
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

from .result import ScanResult
from ..engines.lexical_engine import engine_lexical
from ..engines.entropy_engine import engine_entropy
from ..engines.network_engine import (
    check_dns, check_ssl, check_whois_age,
    check_virustotal, check_google_safebrowsing
)
from ..engines.http_engine import engine_http
from ..ml.scorer import (
    compute_scores, compute_confidence,
    compute_phishing_probability, determine_verdict
)

try:
    import tldextract as _tldextract
    _HAS_TLD = True
except ImportError:
    _HAS_TLD = False


def _normalize(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://","https://","data:","javascript:")):
        url = "https://" + url
    return url


def _parse(url: str):
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.lower()

    if _HAS_TLD:
        ext = _tldextract.extract(url)
        reg_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        tld = f".{ext.suffix}" if ext.suffix else ""
        subdomain = ext.subdomain or ""
    else:
        host = netloc.split(":")[0]
        parts = host.split(".")
        if len(parts) >= 2:
            reg_domain = ".".join(parts[-2:])
            tld = "." + parts[-1]
            subdomain = ".".join(parts[:-2])
        else:
            reg_domain = host
            tld = ""
            subdomain = ""

    return parsed, netloc, reg_domain, tld, subdomain


def _top_summary(checks, n=8):
    failed = sorted(
        [c for c in checks if not c.passed],
        key=lambda c: c.weight, reverse=True
    )
    return [f"[{c.severity.upper()}] {c.name}: {c.detail[:80]}" for c in failed[:n]]


class PhishGuardPro:
    """
    PhishGuard PRO — Production-grade phishing detector.

    Args:
        virustotal_api_key: Free key from virustotal.com (optional but recommended)
        google_safebrowsing_key: Free key from Google Cloud Console (optional)
        enable_whois: Enable WHOIS domain age check (requires python-whois)
        enable_network: Enable DNS/SSL/HTTP checks
        enable_http: Enable HTTP content analysis
    """

    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        google_safebrowsing_key: Optional[str] = None,
        enable_whois: bool = True,
        enable_network: bool = True,
        enable_http: bool = True,
    ):
        self.vt_key = virustotal_api_key
        self.gsb_key = google_safebrowsing_key
        self.enable_whois = enable_whois
        self.enable_network = enable_network
        self.enable_http = enable_http

    def scan(self, url: str) -> ScanResult:
        normalized = _normalize(url)
        parsed, netloc, reg_domain, tld, subdomain = _parse(normalized)
        path = parsed.path or "/"
        query = parsed.query or ""
        host = netloc.split(":")[0]

        result = ScanResult(
            url=url,
            normalized_url=normalized,
            domain=netloc,
            registered_domain=reg_domain,
            tld=tld,
            subdomain=subdomain,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        all_checks = []

        # ── Engine 1: Lexical (always runs) ─────────────────────────────────
        all_checks += engine_lexical(
            normalized, netloc, reg_domain, tld, subdomain, path, query
        )

        # ── Engine 2: Entropy (always runs) ─────────────────────────────────
        all_checks += engine_entropy(
            normalized, netloc, reg_domain, subdomain, path, query
        )

        if self.enable_network:
            # ── Engine 3: DNS ────────────────────────────────────────────────
            resolved_ip, dns_checks = check_dns(host)
            all_checks += dns_checks
            result.resolved_ip = resolved_ip

            # ── Engine 4: SSL ────────────────────────────────────────────────
            ssl_valid, ssl_checks = check_ssl(host, normalized.startswith("https://"))
            all_checks += ssl_checks
            result.ssl_valid = ssl_valid

            # ── Engine 5: WHOIS ──────────────────────────────────────────────
            if self.enable_whois:
                age_days, whois_checks = check_whois_age(reg_domain)
                all_checks += whois_checks
                result.whois_age_days = age_days

            # ── Engine 6: VirusTotal ─────────────────────────────────────────
            vt_pos, vt_total, vt_checks = check_virustotal(normalized, self.vt_key)
            all_checks += vt_checks
            result.virustotal_positives = vt_pos
            result.virustotal_total = vt_total

            # ── Engine 7: Google Safe Browsing ───────────────────────────────
            gsb_checks = check_google_safebrowsing(normalized, self.gsb_key)
            all_checks += gsb_checks

            # ── Engine 8: HTTP Content ───────────────────────────────────────
            if self.enable_http and resolved_ip is not None:
                final_url, http_checks = engine_http(normalized, netloc, reg_domain)
                all_checks += http_checks
                result.final_url = final_url

        # ── ML Scoring ───────────────────────────────────────────────────────
        engine_scores, raw_score = compute_scores(all_checks)
        confidence = compute_confidence(all_checks, raw_score)
        prob = compute_phishing_probability(raw_score, all_checks)
        verdict, verdict_level = determine_verdict(raw_score, prob, all_checks)

        result.checks = all_checks
        result.raw_score = raw_score
        result.confidence = confidence
        result.phishing_probability = prob
        result.verdict = verdict
        result.verdict_level = verdict_level
        result.summary = _top_summary(all_checks)

        # Per-engine scores
        result.structural_score = engine_scores.get("structural", 0)
        result.lexical_score = engine_scores.get("lexical", 0)
        result.entropy_score = engine_scores.get("entropy", 0)
        result.reputation_score = engine_scores.get("reputation", 0)
        result.network_score = engine_scores.get("network", 0)
        result.http_score = engine_scores.get("http", 0)

        return result

    def scan_bulk(self, urls: list) -> list:
        return [self.scan(u) for u in urls]

    def is_phishing(self, url: str) -> bool:
        """Quick boolean check for programmatic use."""
        return self.scan(url).is_phishing

    def get_score(self, url: str) -> float:
        """Quick score (0–100) for programmatic use."""
        return self.scan(url).raw_score
