"""
Network Intelligence Engine
DNS, SSL, WHOIS age, VirusTotal, GeoDB checks.
"""
import socket
import ssl
import ipaddress
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from ..core.result import CheckResult


def _ok(name, detail, evidence=None):
    return CheckResult(name, "network", "info", True, 0.0, detail, evidence)

def _flag(name, severity, weight, detail, evidence=None):
    return CheckResult(name, "network", severity, False, weight, detail, evidence)


# ─────────────────────────────────────────────────────────────────────────────
# DNS ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def check_dns(host: str) -> Tuple[Optional[str], List[CheckResult]]:
    results = []
    resolved_ip = None
    try:
        ip = socket.gethostbyname(host)
        resolved_ip = ip
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            results.append(_flag(
                "DNS → Private IP", "critical", 0.40,
                f"Domain resolves to private IP {ip} — DNS rebinding attack!",
                ip
            ))
        elif ip_obj.is_loopback:
            results.append(_flag(
                "DNS → Loopback", "critical", 0.40,
                f"Domain resolves to loopback {ip} — extremely suspicious",
                ip
            ))
        else:
            results.append(_ok("DNS Resolution", f"Resolves to {ip} ✓", ip))

        # Multiple A records check
        try:
            all_ips = list({r[4][0] for r in socket.getaddrinfo(host, None)})
            if len(all_ips) > 1:
                results.append(_ok("DNS Records", f"{len(all_ips)} IPs found (CDN/load balanced) ✓"))
        except Exception:
            pass

    except socket.gaierror:
        results.append(_flag(
            "DNS Resolution Failed", "high", 0.28,
            f"'{host}' does not resolve — fake, expired, or never-registered domain",
            host
        ))

    return resolved_ip, results


# ─────────────────────────────────────────────────────────────────────────────
# SSL ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def check_ssl(host: str, is_https: bool) -> Tuple[Optional[bool], List[CheckResult]]:
    results = []
    ssl_valid = None

    if not is_https:
        results.append(_flag(
            "No SSL (HTTP)", "medium", 0.10,
            "Site uses plain HTTP — no encryption"
        ))
        return False, results

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(7)
            s.connect((host, 443))
            cert = s.getpeercert()
            ssl_valid = True

            # Expiry check
            exp_str = cert.get("notAfter", "")
            if exp_str:
                exp_dt = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.utcnow()
                days_left = (exp_dt - now).days
                if days_left < 0:
                    ssl_valid = False
                    results.append(_flag(
                        "SSL Certificate Expired", "critical", 0.38,
                        f"Certificate expired {abs(days_left)} days ago",
                        exp_str
                    ))
                elif days_left < 3:
                    results.append(_flag(
                        "SSL Expiring Critically", "high", 0.18,
                        f"Certificate expires in {days_left} days",
                        exp_str
                    ))
                else:
                    results.append(_ok("SSL Expiry", f"Cert valid for {days_left} more days ✓"))

            # Subject check
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "")
            if cn and host not in cn and not cn.startswith("*"):
                # Mismatch
                results.append(_flag(
                    "SSL Subject Mismatch", "high", 0.22,
                    f"Certificate CN '{cn}' does not match host '{host}'",
                    {"cn": cn, "host": host}
                ))
            else:
                results.append(_ok("SSL Subject", f"Certificate matches host ✓"))

            # Issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            issuer_org = issuer.get("organizationName", "Unknown")
            results.append(_ok("SSL Issuer", f"Issued by: {issuer_org} ✓"))

    except ssl.SSLCertVerificationError as e:
        ssl_valid = False
        results.append(_flag(
            "SSL Verification Failed", "critical", 0.42,
            f"Certificate verification error: {str(e)[:80]}",
            str(e)
        ))
    except ssl.SSLError as e:
        ssl_valid = False
        results.append(_flag(
            "SSL Error", "high", 0.25,
            f"SSL error: {str(e)[:80]}",
            str(e)
        ))
    except (ConnectionRefusedError, OSError):
        results.append(_flag(
            "HTTPS Port Unreachable", "high", 0.20,
            "Port 443 unreachable — HTTPS claimed but not available"
        ))
    except Exception as e:
        results.append(_ok("SSL Check", f"SSL inconclusive: {str(e)[:50]}"))

    return ssl_valid, results


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS AGE ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def check_whois_age(domain: str) -> Tuple[Optional[int], List[CheckResult]]:
    """Check domain registration age via python-whois."""
    results = []
    age_days = None
    try:
        import whois  # pip install python-whois
        w = whois.whois(domain)
        created = w.creation_date

        if isinstance(created, list):
            created = created[0]

        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - created).days

            if age_days < 30:
                results.append(_flag(
                    "Newly Registered Domain", "critical", 0.42,
                    f"Domain registered only {age_days} days ago — 94% of phishing domains are <30 days old!",
                    age_days
                ))
            elif age_days < 90:
                results.append(_flag(
                    "Recently Registered Domain", "high", 0.22,
                    f"Domain registered {age_days} days ago — less than 3 months old",
                    age_days
                ))
            elif age_days < 365:
                results.append(_flag(
                    "Young Domain", "medium", 0.08,
                    f"Domain registered {age_days} days ago — less than 1 year old",
                    age_days
                ))
            else:
                years = age_days // 365
                results.append(_ok("Domain Age",
                    f"Domain is {years} year(s) old — established domain ✓"))
        else:
            results.append(_flag(
                "WHOIS Date Missing", "medium", 0.10,
                "Could not retrieve domain creation date — may be privacy-shielded or new"
            ))

    except ImportError:
        results.append(_ok("WHOIS", "python-whois not installed — skipping age check"))
    except Exception as e:
        results.append(_ok("WHOIS", f"WHOIS lookup inconclusive: {str(e)[:60]}"))

    return age_days, results


# ─────────────────────────────────────────────────────────────────────────────
# VIRUSTOTAL ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def check_virustotal(url: str, api_key: Optional[str]) -> Tuple[Optional[int], Optional[int], List[CheckResult]]:
    """Check URL against VirusTotal. Requires free API key."""
    results = []
    positives = None
    total = None

    if not api_key:
        results.append(_ok("VirusTotal",
            "Skipped — provide VIRUSTOTAL_API_KEY for reputation check"))
        return positives, total, results

    try:
        import requests
        import base64

        # VirusTotal v3 URL scan
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=15
        )

        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            if positives >= 5:
                results.append(_flag(
                    "VirusTotal: Malicious", "critical", 0.55,
                    f"{positives}/{total} security vendors flagged this URL as malicious!",
                    stats
                ))
            elif positives >= 2:
                results.append(_flag(
                    "VirusTotal: Suspicious", "high", 0.30,
                    f"{positives}/{total} vendors flagged as suspicious",
                    stats
                ))
            elif positives == 1:
                results.append(_flag(
                    "VirusTotal: Low Risk", "medium", 0.12,
                    f"1/{total} vendor flagged — investigate further",
                    stats
                ))
            else:
                results.append(_ok("VirusTotal",
                    f"0/{total} vendors flagged — clean ✓"))

        elif resp.status_code == 404:
            # URL not in VT database — submit it
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15
            )
            results.append(_ok("VirusTotal",
                "URL not in database — submitted for analysis"))
        else:
            results.append(_ok("VirusTotal",
                f"API returned {resp.status_code} — skipping"))

    except ImportError:
        results.append(_ok("VirusTotal", "requests not installed"))
    except Exception as e:
        results.append(_ok("VirusTotal", f"VT check error: {str(e)[:60]}"))

    return positives, total, results


# ─────────────────────────────────────────────────────────────────────────────
# GOOGLE SAFE BROWSING ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def check_google_safebrowsing(url: str, api_key: Optional[str]) -> List[CheckResult]:
    """Check URL against Google Safe Browsing API v4."""
    results = []
    if not api_key:
        results.append(_ok("Google Safe Browsing",
            "Skipped — provide GOOGLE_SAFEBROWSING_API_KEY"))
        return results
    try:
        import requests
        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "3.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload, timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = [m.get("threatType","?") for m in matches]
                results.append(_flag(
                    "Google Safe Browsing: THREAT", "critical", 0.55,
                    f"Google flagged as: {', '.join(threat_types)}",
                    threat_types
                ))
            else:
                results.append(_ok("Google Safe Browsing", "Not in Google threat database ✓"))
    except ImportError:
        results.append(_ok("Google Safe Browsing", "requests not installed"))
    except Exception as e:
        results.append(_ok("Google Safe Browsing", f"Error: {str(e)[:60]}"))
    return results
