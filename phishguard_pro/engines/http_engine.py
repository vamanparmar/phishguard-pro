"""
HTTP Content Analysis Engine
Deep page inspection: redirects, security headers, HTML phishing signals.
"""
import re
import urllib.parse
from typing import List, Tuple, Optional
from ..core.result import CheckResult


def _ok(name, detail, evidence=None):
    return CheckResult(name, "http", "info", True, 0.0, detail, evidence)

def _flag(name, severity, weight, detail, evidence=None):
    return CheckResult(name, "http", severity, False, weight, detail, evidence)


# Phishing HTML signals
PHISHING_HTML_PATTERNS = [
    (r"verify\s+your\s+account",           "critical", 0.35, "Verify your account prompt"),
    (r"confirm\s+your\s+identity",         "critical", 0.35, "Confirm identity prompt"),
    (r"account\s+(has\s+been\s+)?suspend", "critical", 0.35, "Account suspension notice"),
    (r"unusual\s+(sign-in|login|activity)","critical", 0.35, "Unusual activity notice"),
    (r"your\s+account\s+will\s+be\s+clos","critical", 0.35, "Account closure threat"),
    (r"update\s+your\s+payment",           "high",     0.25, "Payment update request"),
    (r"enter\s+your\s+(password|pin|cvv)", "high",     0.28, "Credential entry prompt"),
    (r"social\s+security\s+number",        "high",     0.30, "SSN request"),
    (r"credit\s+card\s+number",            "high",     0.28, "Credit card request"),
    (r"bank\s+account\s+number",           "high",     0.28, "Bank account request"),
    (r"you\s+have\s+(won|been\s+selected)","high",     0.25, "Prize/scam lure"),
    (r"congratulations.*prize",            "high",     0.25, "Prize/scam lure"),
    (r"<iframe[^>]+src=[\"'][^\"']*http",  "high",     0.22, "External iframe loaded"),
    (r"document\.location\s*=",           "medium",   0.15, "JavaScript forced redirect"),
    (r"window\.location\s*=",             "medium",   0.15, "JavaScript forced redirect"),
    (r"eval\s*\(",                         "medium",   0.18, "eval() in page — obfuscation"),
    (r"base64_decode",                     "medium",   0.15, "Base64 decode — obfuscation"),
    (r"fromcharcode",                      "medium",   0.15, "String obfuscation"),
    (r"unescape\s*\(",                     "medium",   0.12, "String obfuscation"),
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "x-xss-protection",
    "referrer-policy",
]


def engine_http(url: str, netloc: str, original_domain: str) -> Tuple[Optional[str], List[CheckResult]]:
    results = []
    final_url = None

    try:
        import requests
    except ImportError:
        results.append(_ok("HTTP Engine", "Skipped — install 'requests' for HTTP analysis"))
        return final_url, results

    try:
        resp = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            headers={
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36"),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
            },
            verify=True,
            stream=False,
        )
        final_url = resp.url

        # ── 1. Redirect analysis ───────────────────────────────────────────
        if resp.history:
            chain = [r.url for r in resp.history] + [resp.url]
            final_netloc = urllib.parse.urlparse(resp.url).netloc.lower()

            if final_netloc != netloc.split(":")[0].lower():
                results.append(_flag(
                    "Cross-Domain Redirect", "high", 0.25,
                    f"Redirected from '{netloc}' to different domain '{final_netloc}'",
                    {"chain": chain[:5]}
                ))
            elif len(resp.history) > 4:
                results.append(_flag(
                    "Excessive Redirect Chain", "medium", 0.14,
                    f"{len(resp.history)} redirects before destination",
                    chain[:5]
                ))
            else:
                results.append(_ok("Redirect Chain",
                    f"{len(resp.history)} redirect(s), same domain ✓"))
        else:
            results.append(_ok("Redirect Check", "No redirects ✓"))

        # ── 2. HTTP Status ─────────────────────────────────────────────────
        if resp.status_code == 200:
            results.append(_ok("HTTP Status", "200 OK ✓"))
        elif resp.status_code in (301, 302, 303, 307, 308):
            results.append(_ok("HTTP Status", f"{resp.status_code} redirect — followed ✓"))
        elif resp.status_code == 404:
            results.append(_flag("HTTP 404", "low", 0.05,
                                  "Page not found — URL may be invalid or taken down"))
        elif resp.status_code >= 500:
            results.append(_flag("Server Error", "low", 0.05,
                                  f"HTTP {resp.status_code} — server error"))

        # ── 3. Security headers ────────────────────────────────────────────
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        missing = [h for h in SECURITY_HEADERS if h not in headers_lower]
        if len(missing) >= 4:
            results.append(_flag(
                "Missing Security Headers", "medium", 0.12,
                f"Missing {len(missing)}/6 security headers: {missing[:3]}",
                missing
            ))
        elif missing:
            results.append(_flag(
                "Some Security Headers Missing", "low", 0.05,
                f"Missing: {missing}",
                missing
            ))
        else:
            results.append(_ok("Security Headers", "All major security headers present ✓"))

        # ── 4. Content-Type & page analysis ───────────────────────────────
        content_type = headers_lower.get("content-type", "")
        if "text/html" not in content_type:
            results.append(_ok("Content Type", f"Non-HTML content ({content_type}) ✓"))
        else:
            html = resp.text[:20000].lower()

            # Check for phishing HTML signals
            html_hits = []
            for pattern, sev, weight, desc in PHISHING_HTML_PATTERNS:
                if re.search(pattern, html, re.IGNORECASE):
                    html_hits.append((desc, sev, weight))

            if html_hits:
                max_weight = max(w for _, _, w in html_hits)
                worst_sev = "critical" if any(s=="critical" for _,s,_ in html_hits) else "high"
                results.append(_flag(
                    "Phishing Page Content", worst_sev, max_weight,
                    f"{len(html_hits)} phishing signals in page HTML: {[d for d,_,_ in html_hits[:3]]}",
                    html_hits
                ))
            else:
                results.append(_ok("HTML Content", "No phishing signals in page HTML ✓"))

            # Check for brand logos/favicon on wrong domain
            for brand in ["paypal", "google", "facebook", "apple", "amazon",
                          "microsoft", "netflix", "instagram"]:
                if brand in html:
                    official = [d for d in (
                        __import__("phishguard_pro.core.threat_intel",
                                   fromlist=["BRAND_OFFICIAL_DOMAINS"])
                        .BRAND_OFFICIAL_DOMAINS.get(brand, []))
                    ]
                    if official and not any(d in resp.url for d in official):
                        results.append(_flag(
                            f"Brand Content on Wrong Domain", "critical", 0.38,
                            f"'{brand}' branding found in page but URL is not on official {brand} domain",
                            {"brand": brand, "url": resp.url[:80]}
                        ))
                        break

            # Password form on non-HTTPS
            if re.search(r'input[^>]+type=["\']password["\']', html):
                if not resp.url.startswith("https://"):
                    results.append(_flag(
                        "Password Form Over HTTP", "critical", 0.40,
                        "Password input field served over unencrypted HTTP!",
                    ))
                else:
                    results.append(_ok("Password Form", "Password form served over HTTPS ✓"))

            # External form action (submits to different domain)
            form_action = re.search(r'<form[^>]+action=["\']https?://([^/"\']+)', html)
            if form_action:
                action_domain = form_action.group(1)
                if action_domain and action_domain.lower() != netloc.split(":")[0].lower():
                    results.append(_flag(
                        "Form Submits to External Domain", "critical", 0.45,
                        f"Form action points to external domain '{action_domain}' — credentials harvested!",
                        action_domain
                    ))
                else:
                    results.append(_ok("Form Action", "Form submits to same domain ✓"))

            # Favicon check — phishing sites steal favicons
            if re.search(r'favicon.*\.(ico|png)', html):
                results.append(_ok("Favicon", "Favicon present ✓"))

            # Hidden fields (common in phishing to pass stolen data)
            hidden = re.findall(r'<input[^>]+type=["\']hidden["\']', html)
            if len(hidden) > 10:
                results.append(_flag(
                    "Excessive Hidden Form Fields", "medium", 0.12,
                    f"{len(hidden)} hidden input fields — may be exfiltrating data",
                    len(hidden)
                ))

        # ── 5. X-Frame-Options ────────────────────────────────────────────
        xfo = headers_lower.get("x-frame-options", "")
        if not xfo:
            results.append(_flag(
                "No Clickjacking Protection", "low", 0.05,
                "Missing X-Frame-Options — site could be framed for clickjacking"
            ))

    except requests.exceptions.SSLError as e:
        results.append(_flag(
            "SSL Connection Error", "critical", 0.38,
            "SSL certificate error during connection",
            str(e)[:80]
        ))
    except requests.exceptions.ConnectionError:
        results.append(_flag(
            "Connection Failed", "high", 0.22,
            "Cannot connect — site may be down, fake, or actively blocking"
        ))
    except requests.exceptions.Timeout:
        results.append(_flag(
            "Connection Timeout", "medium", 0.10,
            "Site timed out — slow/suspicious server"
        ))
    except Exception as e:
        results.append(_ok("HTTP Engine", f"Inconclusive: {str(e)[:60]}"))

    return final_url, results
