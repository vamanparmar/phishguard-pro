"""
Lexical Analysis Engine
Deep textual/linguistic analysis of URL components.
"""
import re
import unicodedata
import urllib.parse
from typing import List
from ..core.result import CheckResult
from ..core.threat_intel import (
    BRAND_OFFICIAL_DOMAINS, ALL_BRAND_KEYWORDS, DOMAIN_TO_BRAND,
    CRITICAL_RISK_TLDS, HIGH_RISK_TLDS, MEDIUM_RISK_TLDS,
    URL_SHORTENERS, KEYWORDS_CRITICAL, KEYWORDS_HIGH,
    KEYWORDS_MEDIUM, KEYWORDS_LURE, DANGEROUS_EXTENSIONS,
    HOMOGLYPHS, WHITELIST_DOMAINS,
    PATTERN_IP, PATTERN_HEX, PATTERN_JS_INJECT,
    PATTERN_PHISH_PATH, PATTERN_REPEATED_CHARS,
)


def _ok(name, detail):
    return CheckResult(name, "lexical", "info", True, 0.0, detail)

def _flag(name, severity, weight, detail, evidence=None):
    return CheckResult(name, "lexical", severity, False, weight, detail, evidence)


def _levenshtein(s1: str, s2: str) -> int:
    if abs(len(s1) - len(s2)) > 4:
        return 999
    m, n = len(s1), len(s2)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            dp[j] = prev[j-1] if s1[i-1] == s2[j-1] else 1 + min(prev[j], dp[j-1], prev[j-1])
    return dp[n]


def _normalize_leet(s: str) -> str:
    """Convert leetspeak to plain letters for matching."""
    table = {"0":"o","1":"l","3":"e","4":"a","5":"s","6":"g",
             "7":"t","8":"b","@":"a","$":"s","!":"i","9":"g"}
    return "".join(table.get(c, c) for c in s.lower())


def engine_lexical(url: str, netloc: str, reg_domain: str,
                   tld: str, subdomain: str, path: str, query: str) -> List[CheckResult]:
    results = []
    url_lower = url.lower()
    host = netloc.split(":")[0].lower()

    # ── Whitelist fast-exit ──────────────────────────────────────────────────
    for wl in WHITELIST_DOMAINS:
        if reg_domain == wl or reg_domain.endswith("." + wl):
            results.append(_ok("Whitelisted Domain",
                               f"'{reg_domain}' is a known legitimate domain ✓"))
            return results  # Trusted — skip all other lexical checks

    # ── 1. Brand impersonation ───────────────────────────────────────────────
    spoofed = []
    for brand in ALL_BRAND_KEYWORDS:
        if brand in url_lower:
            official_list = BRAND_OFFICIAL_DOMAINS.get(brand, [])
            if official_list and reg_domain not in official_list:
                spoofed.append((brand, official_list[0]))
    if spoofed:
        b, o = spoofed[0]
        results.append(_flag(
            "Brand Impersonation", "critical", 0.40,
            f"'{b}' appears in URL but real domain is '{reg_domain}' (official: {o})",
            spoofed
        ))
    else:
        results.append(_ok("Brand Check", "No brand impersonation detected ✓"))

    # ── 2. Official domain used as subdomain (most dangerous trick) ─────────
    for brand, official_list in BRAND_OFFICIAL_DOMAINS.items():
        for od in official_list:
            if od in host and not host.endswith(od) and od != reg_domain:
                results.append(_flag(
                    "Official Domain as Subdomain", "critical", 0.50,
                    f"'{od}' appears as subdomain of '{reg_domain}' — #1 phishing trick!",
                    {"host": host, "spoofed": od}
                ))
                break

    # ── 3. Typosquatting (edit distance) ────────────────────────────────────
    base = reg_domain.rsplit(".", 1)[0] if "." in reg_domain else reg_domain
    typo_hit = None
    for brand, official_list in BRAND_OFFICIAL_DOMAINS.items():
        for od in official_list:
            ob = od.rsplit(".", 1)[0]
            dist = _levenshtein(base, ob)
            if 0 < dist <= 2 and len(base) > 4:
                typo_hit = (reg_domain, od, dist)
                break
        if typo_hit:
            break
    if typo_hit:
        results.append(_flag(
            "Typosquatting", "critical", 0.38,
            f"'{typo_hit[0]}' is {typo_hit[2]} edit(s) from '{typo_hit[1]}' — classic typosquat",
            typo_hit
        ))
    else:
        results.append(_ok("Typosquatting Check", "No typosquatting detected ✓"))

    # ── 4. Leetspeak brand spoofing ──────────────────────────────────────────
    norm_base = _normalize_leet(base)
    leet_hits = []
    for brand in ALL_BRAND_KEYWORDS:
        norm_brand = _normalize_leet(brand)
        if norm_brand in norm_base and brand not in base:
            official = BRAND_OFFICIAL_DOMAINS.get(brand, [])
            if not official or reg_domain not in official:
                leet_hits.append(brand)
    if leet_hits:
        results.append(_flag(
            "Leetspeak Brand Spoofing", "critical", 0.36,
            f"Domain '{reg_domain}' uses character substitution to impersonate: {leet_hits}",
            leet_hits
        ))
    else:
        results.append(_ok("Leetspeak Check", "No leetspeak brand substitution ✓"))

    # ── 5. Homograph / Unicode attack ───────────────────────────────────────
    try:
        host.encode("ascii")
        results.append(_ok("Homograph Check", "All ASCII characters ✓"))
    except UnicodeEncodeError:
        non_ascii = [(i, c, unicodedata.name(c, "?"), unicodedata.category(c))
                     for i, c in enumerate(host) if ord(c) > 127]
        results.append(_flag(
            "Homograph Attack", "critical", 0.45,
            f"Non-ASCII Unicode characters found — lookalike attack (e.g. Cyrillic 'а' → Latin 'a')",
            non_ascii[:5]
        ))

    # ── 6. Punycode ─────────────────────────────────────────────────────────
    if "xn--" in host:
        results.append(_flag(
            "Punycode Domain", "high", 0.20,
            f"IDN punycode domain — often used to create lookalike URLs",
            host
        ))
    else:
        results.append(_ok("Punycode Check", "No punycode encoding ✓"))

    # ── 7. TLD risk ──────────────────────────────────────────────────────────
    if tld in CRITICAL_RISK_TLDS:
        results.append(_flag(
            "Critical-Risk TLD", "critical", 0.28,
            f"TLD '{tld}' is the most abused in phishing (Freenom free domains)",
            tld
        ))
    elif tld in HIGH_RISK_TLDS:
        results.append(_flag(
            "High-Risk TLD", "high", 0.18,
            f"TLD '{tld}' frequently appears in phishing campaigns",
            tld
        ))
    elif tld in MEDIUM_RISK_TLDS:
        results.append(_flag(
            "Medium-Risk TLD", "medium", 0.08,
            f"TLD '{tld}' has moderate association with spam/phishing",
            tld
        ))
    else:
        results.append(_ok("TLD Check", f"TLD '{tld}' is not in risk lists ✓"))

    # ── 8. Critical phishing keywords ────────────────────────────────────────
    crit_kw = [k for k in KEYWORDS_CRITICAL if k in url_lower]
    if crit_kw:
        results.append(_flag(
            "Critical Phishing Phrases", "critical", 0.30,
            f"Critical phishing phrase(s) detected: {crit_kw}",
            crit_kw
        ))
    else:
        results.append(_ok("Critical Keywords", "No critical phishing phrases ✓"))

    # ── 9. High-severity keywords ────────────────────────────────────────────
    high_kw = [k for k in KEYWORDS_HIGH if k in url_lower]
    score = min(len(high_kw) * 0.06, 0.22)
    if len(high_kw) >= 3:
        results.append(_flag(
            "Multiple Phishing Keywords", "high", score,
            f"{len(high_kw)} high-severity phishing terms: {high_kw[:5]}",
            high_kw
        ))
    elif high_kw:
        results.append(_flag(
            "Phishing Keywords", "medium", score,
            f"Phishing-related keywords: {high_kw}",
            high_kw
        ))
    else:
        results.append(_ok("High Keywords", "No high-severity phishing keywords ✓"))

    # ── 10. Lure/scam keywords ───────────────────────────────────────────────
    lure_kw = [k for k in KEYWORDS_LURE if k in url_lower]
    if lure_kw:
        results.append(_flag(
            "Scam/Lure Keywords", "high", 0.18,
            f"Scam lure terms detected: {lure_kw}",
            lure_kw
        ))
    else:
        results.append(_ok("Lure Keywords", "No scam/lure keywords ✓"))

    # ── 11. URL shortener ────────────────────────────────────────────────────
    if reg_domain in URL_SHORTENERS:
        results.append(_flag(
            "URL Shortener", "medium", 0.15,
            f"URL shortened via '{reg_domain}' — hides real destination",
            reg_domain
        ))
    else:
        results.append(_ok("Shortener Check", "Not a URL shortener ✓"))

    # ── 12. Hyphens in domain ────────────────────────────────────────────────
    hyp = base.count("-")
    if hyp >= 4:
        results.append(_flag(
            "Excessive Hyphens", "high", 0.16,
            f"{hyp} hyphens in '{base}' — phishing domains use hyphens to fake legitimacy",
            hyp
        ))
    elif hyp >= 2:
        results.append(_flag(
            "Multiple Hyphens", "medium", 0.07,
            f"{hyp} hyphens in domain — moderately suspicious",
            hyp
        ))
    else:
        results.append(_ok("Hyphen Check", f"{hyp} hyphen(s) in domain ✓"))

    # ── 13. Dangerous path patterns ──────────────────────────────────────────
    pm = PATTERN_PHISH_PATH.search(path)
    if pm:
        results.append(_flag(
            "Malicious Path Pattern", "high", 0.20,
            f"Path targets '{pm.group()}' — probing for known vulnerabilities",
            pm.group()
        ))
    else:
        results.append(_ok("Path Check", "No malicious path patterns ✓"))

    # ── 14. Dangerous file extension ─────────────────────────────────────────
    path_lower = path.lower()
    for ext, desc in DANGEROUS_EXTENSIONS.items():
        if path_lower.endswith(ext):
            results.append(_flag(
                "Dangerous File Type", "critical", 0.40,
                f"URL delivers '{ext}' ({desc}) — do NOT download!",
                ext
            ))
            break
    else:
        results.append(_ok("Extension Check", "No dangerous file extension ✓"))

    # ── 15. @ symbol trick ───────────────────────────────────────────────────
    if "@" in url:
        creds = url.split("@")[0].replace("https://","").replace("http://","")
        results.append(_flag(
            "Credential @ Trick", "critical", 0.40,
            f"'@' in URL hides real destination — '{creds}' is fake prefix",
            creds
        ))
    else:
        results.append(_ok("@ Symbol Check", "No @ trick ✓"))

    # ── 16. Multiple subdomains ───────────────────────────────────────────────
    sub_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    if len(sub_parts) >= 5:
        results.append(_flag(
            "Excessive Subdomains", "critical", 0.32,
            f"{len(sub_parts)} subdomain levels — deep nesting hides real domain",
            sub_parts
        ))
    elif len(sub_parts) >= 3:
        results.append(_flag(
            "Deep Subdomains", "high", 0.14,
            f"{len(sub_parts)} subdomain levels — investigate carefully",
            sub_parts
        ))
    else:
        results.append(_ok("Subdomain Depth", f"{len(sub_parts)} subdomain level(s) ✓"))

    # ── 17. Script injection in URL ───────────────────────────────────────────
    if PATTERN_JS_INJECT.search(url):
        results.append(_flag(
            "Script Injection", "critical", 0.50,
            "javascript:/vbscript:/data:text/html in URL — direct code injection!",
        ))
    else:
        results.append(_ok("Script Injection", "No script injection ✓"))

    # ── 18. Heavy URL encoding ────────────────────────────────────────────────
    hex_count = len(PATTERN_HEX.findall(url))
    if hex_count > 15:
        results.append(_flag(
            "Heavy Obfuscation", "high", 0.20,
            f"{hex_count} percent-encoded chars — hides malicious payload",
            hex_count
        ))
    elif hex_count > 6:
        results.append(_flag(
            "Moderate Encoding", "medium", 0.08,
            f"{hex_count} percent-encoded chars",
            hex_count
        ))
    else:
        results.append(_ok("URL Encoding", f"{hex_count} encoded chars — normal ✓"))

    # ── 19. Protocol check ────────────────────────────────────────────────────
    if url.startswith("http://"):
        results.append(_flag(
            "Insecure HTTP", "medium", 0.10,
            "Unencrypted HTTP — credentials visible to attackers on same network"
        ))
    else:
        results.append(_ok("Protocol", "HTTPS used ✓"))

    # ── 20. IP address URL ────────────────────────────────────────────────────
    import ipaddress
    try:
        ipaddress.ip_address(host)
        results.append(_flag(
            "Raw IP Address", "critical", 0.35,
            f"URL uses IP address {host} — legitimate sites don't do this for banking/login",
            host
        ))
    except ValueError:
        results.append(_ok("IP Check", "Domain name used (not raw IP) ✓"))

    # ── 21. URL length ────────────────────────────────────────────────────────
    ln = len(url)
    if ln > 150:
        results.append(_flag("Extreme URL Length", "high", 0.16,
                              f"{ln} chars — obfuscation through length", ln))
    elif ln > 100:
        results.append(_flag("Long URL", "medium", 0.07,
                              f"{ln} chars — moderately long", ln))
    else:
        results.append(_ok("URL Length", f"{ln} chars ✓"))

    # ── 22. Port anomaly ─────────────────────────────────────────────────────
    if ":" in netloc:
        try:
            port = int(netloc.split(":")[-1])
            if port not in (80, 443, 8080, 8443):
                results.append(_flag(
                    "Unusual Port", "medium", 0.10,
                    f"Non-standard port {port} — legitimate banking/auth sites use 443",
                    port
                ))
        except ValueError:
            pass

    # ── 23. Suspicious double slash ──────────────────────────────────────────
    clean_path = re.sub(r"^//", "", path)
    if "//" in clean_path:
        results.append(_flag(
            "Double-Slash Redirect", "high", 0.18,
            "'//' in path — open redirect abuse"
        ))

    return results
