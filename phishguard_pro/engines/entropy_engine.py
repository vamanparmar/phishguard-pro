"""
Entropy & Statistical Feature Engine
Uses mathematical analysis to detect auto-generated / DGA domains.
"""
import math
import re
from typing import List, Tuple
from ..core.result import CheckResult


def _ok(name, detail):
    return CheckResult(name, "entropy", "info", True, 0.0, detail)

def _flag(name, severity, weight, detail, evidence=None):
    return CheckResult(name, "entropy", severity, False, weight, detail, evidence)


def _entropy(s: str) -> float:
    """Shannon entropy of a string. Higher = more random = suspicious."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())


def _consonant_ratio(s: str) -> float:
    """Ratio of consonants. Real words have ~60% consonants. DGA = high."""
    consonants = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in consonants) / len(letters)


def _digit_ratio(s: str) -> float:
    """Ratio of digits in string."""
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)


def _vowel_ratio(s: str) -> float:
    vowels = set("aeiouAEIOU")
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in vowels) / len(letters)


def _longest_consonant_run(s: str) -> int:
    """Longest run of consecutive consonants. Real words rarely exceed 4."""
    consonants = set("bcdfghjklmnpqrstvwxyz")
    max_run = cur = 0
    for c in s.lower():
        if c in consonants:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 0
    return max_run


def _has_dga_pattern(domain: str) -> Tuple[bool, str]:
    """
    Domain Generation Algorithm detection.
    DGA domains look like: a3k9mxp2.com, xyzqrfhj.net
    """
    # Remove TLD
    base = domain.rsplit(".", 1)[0] if "." in domain else domain

    ent = _entropy(base)
    cons_ratio = _consonant_ratio(base)
    digit_r = _digit_ratio(base)
    longest_cons = _longest_consonant_run(base)
    vowel_r = _vowel_ratio(base)

    flags = []

    if ent > 3.8 and len(base) >= 8:
        flags.append(f"high entropy ({ent:.2f})")
    if cons_ratio > 0.75 and len(base) > 6:
        flags.append(f"high consonant ratio ({cons_ratio:.0%})")
    if digit_r > 0.35:
        flags.append(f"high digit ratio ({digit_r:.0%})")
    if longest_cons >= 5:
        flags.append(f"consonant run of {longest_cons}")
    if vowel_r < 0.15 and len(base) > 5:
        flags.append(f"almost no vowels ({vowel_r:.0%})")

    return bool(flags), ", ".join(flags)


def engine_entropy(url: str, netloc: str, reg_domain: str,
                   subdomain: str, path: str, query: str) -> List[CheckResult]:
    results = []
    base_domain = reg_domain.rsplit(".", 1)[0] if "." in reg_domain else reg_domain

    # 1. Full URL entropy
    url_entropy = _entropy(url)
    if url_entropy > 4.5:
        results.append(_flag(
            "High URL Entropy", "high", 0.20,
            f"URL entropy {url_entropy:.2f} — extremely random, typical of auto-generated phishing URLs",
            url_entropy
        ))
    elif url_entropy > 4.0:
        results.append(_flag(
            "Elevated URL Entropy", "medium", 0.10,
            f"URL entropy {url_entropy:.2f} — moderately suspicious randomness",
            url_entropy
        ))
    else:
        results.append(_ok("URL Entropy", f"URL entropy {url_entropy:.2f} — normal ✓"))

    # 2. Domain entropy
    dom_entropy = _entropy(base_domain)
    if dom_entropy > 3.5 and len(base_domain) >= 8:
        results.append(_flag(
            "High Domain Entropy", "high", 0.18,
            f"Domain entropy {dom_entropy:.2f} — looks auto-generated (DGA pattern)",
            dom_entropy
        ))
    else:
        results.append(_ok("Domain Entropy", f"Domain entropy {dom_entropy:.2f} — looks human-chosen ✓"))

    # 3. DGA detection
    is_dga, dga_reason = _has_dga_pattern(reg_domain)
    if is_dga:
        results.append(_flag(
            "DGA Domain Detected", "high", 0.22,
            f"Domain matches Domain Generation Algorithm pattern: {dga_reason}",
            dga_reason
        ))
    else:
        results.append(_ok("DGA Check", "Domain does not match DGA patterns ✓"))

    # 4. Subdomain entropy
    if subdomain and len(subdomain) > 4:
        sub_entropy = _entropy(subdomain.replace(".", ""))
        if sub_entropy > 3.8:
            results.append(_flag(
                "Random Subdomain", "medium", 0.12,
                f"Subdomain '{subdomain}' looks randomly generated (entropy {sub_entropy:.2f})",
                sub_entropy
            ))
        else:
            results.append(_ok("Subdomain Entropy", f"Subdomain looks normal (entropy {sub_entropy:.2f}) ✓"))

    # 5. Path entropy
    if path and len(path) > 10:
        path_entropy = _entropy(path)
        if path_entropy > 4.2:
            results.append(_flag(
                "Obfuscated Path", "medium", 0.10,
                f"URL path has high entropy {path_entropy:.2f} — likely obfuscated/encoded payload",
                path_entropy
            ))

    # 6. Query string entropy
    if query and len(query) > 20:
        q_entropy = _entropy(query)
        if q_entropy > 4.5:
            results.append(_flag(
                "Obfuscated Query String", "medium", 0.10,
                f"Query string entropy {q_entropy:.2f} — encoded/obfuscated parameters",
                q_entropy
            ))

    # 7. Vowel starvation (xzplqk.com style)
    vowel_r = _vowel_ratio(base_domain)
    if vowel_r < 0.12 and len(base_domain) > 5:
        results.append(_flag(
            "Vowel Starvation", "medium", 0.14,
            f"Only {vowel_r:.0%} vowels in domain '{base_domain}' — humans don't naturally write this",
            vowel_r
        ))
    else:
        results.append(_ok("Vowel Analysis", f"Normal vowel distribution ({vowel_r:.0%}) ✓"))

    # 8. Repeated character patterns
    if re.search(r"(.)\1{3,}", base_domain):
        results.append(_flag(
            "Repeated Characters", "low", 0.07,
            f"Unusual character repetition in domain '{base_domain}'",
            base_domain
        ))

    # 9. Domain length analysis
    dom_len = len(base_domain)
    if dom_len > 30:
        results.append(_flag(
            "Extremely Long Domain", "high", 0.15,
            f"Domain base is {dom_len} characters — real brands use short memorable names",
            dom_len
        ))
    elif dom_len > 20:
        results.append(_flag(
            "Long Domain Name", "medium", 0.08,
            f"Domain base is {dom_len} characters — unusually long",
            dom_len
        ))
    else:
        results.append(_ok("Domain Length", f"Domain length {dom_len} chars — reasonable ✓"))

    return results
