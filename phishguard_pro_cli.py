#!/usr/bin/env python3
"""
PhishGuard PRO v3.0 — CLI
Highest-accuracy phishing & malicious URL detection.

Usage:
    python phishguard_pro_cli.py                         # Interactive mode
    python phishguard_pro_cli.py --demo                  # Run test suite
    python phishguard_pro_cli.py https://example.com     # Direct scan
    python phishguard_pro_cli.py --vt-key YOUR_KEY url   # With VirusTotal
    python phishguard_pro_cli.py --offline url           # No network
"""
import sys
import os
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishguard_pro import PhishGuardPro
from phishguard_pro.utils.reporter import banner, render, bulk_summary


# ─────────────────────────────────────────────────────────────────────────────
# DEMO TEST SUITE  (designed to exercise every engine)
# ─────────────────────────────────────────────────────────────────────────────
DEMO_SUITE = [
    # ── SAFE ──
    ("https://www.google.com",                          "SAFE — Google"),
    ("https://github.com",                              "SAFE — GitHub"),
    ("https://www.amazon.in/gp/cart/view.html",         "SAFE — Amazon India"),
    ("https://www.hdfcbank.com/personal/pay/cards",     "SAFE — HDFC Bank"),

    # ── STRUCTURAL ──
    ("http://192.168.0.1/banking/login",                "CRITICAL — Raw IP"),
    ("http://paypal.com.secure.login.evil.tk/@verify",  "CRITICAL — Subdomain+TLD+@ trick"),

    # ── BRAND IMPERSONATION ──
    ("https://paypal-secure-account-verify.com/signin", "HIGH — PayPal spoof"),
    ("https://amazon-india-prime-refund.xyz/claim",     "HIGH — Amazon+scam TLD"),
    ("https://microsoft-login-office365.club/auth",     "HIGH — Microsoft spoof"),
    ("https://hdfc-bank-netbanking-update.tk/verify",   "CRITICAL — HDFC Bank spoof"),
    ("https://sbi-online-update-kyc.ml/kyc",            "CRITICAL — SBI KYC phishing"),
    ("https://irctc-refund-claim.tk/refund",            "CRITICAL — IRCTC phishing"),

    # ── TYPOSQUATTING ──
    ("https://paypa1.com/login",                        "CRITICAL — Leetspeak paypal"),
    ("https://gooogle.com/account/verify",              "HIGH — Google typosquat"),
    ("https://facebo0k.com/login",                      "CRITICAL — Facebook spoof"),

    # ── ENTROPY / DGA ──
    ("https://xzqkfmpr.tk/payload",                     "HIGH — DGA domain"),
    ("https://a3k9mxp2zqr.com/gate.php",                "HIGH — Entropy + DGA"),

    # ── HOMOGRAPH ──
    ("https://аpple.com/id/login",                      "CRITICAL — Cyrillic homograph"),

    # ── SCAM LURE ──
    ("http://free-iphone16-winner.party/claim-now",     "HIGH — Scam lure"),
    ("https://bit.ly/3xPhish1ng",                       "MEDIUM — URL shortener"),
]


def run_demo(guard, verbose):
    try:
        from colorama import Fore, Style
        print(Fore.CYAN + Style.BRIGHT + f"\n  DEMO MODE — {len(DEMO_SUITE)} test URLs" + Style.RESET_ALL)
    except ImportError:
        print(f"\n  DEMO MODE — {len(DEMO_SUITE)} test URLs")

    results = []
    for url, note in DEMO_SUITE:
        print(f"\n  » {note}")
        result = guard.scan(url)
        results.append(result)
        render(result, verbose=verbose)

    bulk_summary(results)
    return results


def run_interactive(guard, verbose):
    try:
        from colorama import Fore, Style
        PROMPT = Fore.CYAN + Style.BRIGHT + "\n  Enter URL(s) [comma-separated | quit | export | verbose on/off]: " + Style.RESET_ALL
    except ImportError:
        PROMPT = "\n  Enter URL(s) [comma-separated | quit | export | verbose on/off]: "

    print("\n  INTERACTIVE MODE — Paste any URL to scan")
    print("  ─────────────────────────────────────────────────────")

    session = []

    while True:
        try:
            user_input = input(PROMPT).strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd in ("quit","exit","q"):
            break
        if cmd == "verbose on":
            verbose = True; print("  Verbose ON"); continue
        if cmd == "verbose off":
            verbose = False; print("  Verbose OFF"); continue
        if cmd in ("export","export-json"):
            if session:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = f"phishguard_report_{ts}.json"
                with open(path, "w") as f:
                    data = {
                        "generated": datetime.now().isoformat(),
                        "total": len(session),
                        "results": [r.to_dict() for r in session]
                    }
                    json.dump(data, f, indent=2, default=str)
                print(f"  ✓ Saved {len(session)} results → {path}")
            else:
                print("  No results yet.")
            continue
        if cmd == "export-csv":
            if session:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = f"phishguard_report_{ts}.csv"
                import csv
                with open(path, "w", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["URL","Domain","Score","Probability","Level","Verdict","Top Finding"])
                    for r in session:
                        w.writerow([r.url, r.registered_domain,
                                    f"{r.raw_score:.1f}", f"{r.phishing_probability:.4f}",
                                    r.verdict_level, r.verdict,
                                    r.summary[0][:80] if r.summary else ""])
                print(f"  ✓ CSV saved → {path}")
            continue

        urls = [u.strip() for u in user_input.split(",") if u.strip()]
        for u in urls:
            result = guard.scan(u)
            session.append(result)
            render(result, verbose=verbose)

        if len(urls) > 1:
            bulk_summary([r for r in session[-len(urls):]])

    if session:
        print(f"\n  Session: {len(session)} URL(s) scanned.")

    try:
        from colorama import Fore, Style
        print(Fore.GREEN + Style.BRIGHT + "\n  Stay safe online — PhishGuard PRO\n" + Style.RESET_ALL)
    except ImportError:
        print("\n  Stay safe online — PhishGuard PRO\n")


def main():
    p = argparse.ArgumentParser(description="PhishGuard PRO — Enterprise URL Threat Detection")
    p.add_argument("urls", nargs="*", help="URL(s) to scan")
    p.add_argument("--demo", action="store_true", help="Run built-in test suite")
    p.add_argument("--offline", action="store_true", help="Disable all network checks")
    p.add_argument("--no-whois", action="store_true", help="Skip WHOIS age check")
    p.add_argument("--vt-key", metavar="KEY", help="VirusTotal API key")
    p.add_argument("--gsb-key", metavar="KEY", help="Google Safe Browsing API key")
    p.add_argument("--verbose", "-v", action="store_true", help="Show raw evidence")
    p.add_argument("--quiet", "-q", action="store_true", help="One-line output per URL (scripting)")
    p.add_argument("--json", action="store_true", help="Output raw JSON")
    p.add_argument("--export-json", metavar="FILE", help="Save JSON report")
    p.add_argument("--export-csv", metavar="FILE", help="Save CSV report")
    args = p.parse_args()

    # Read API keys from environment if not provided
    vt_key  = args.vt_key  or os.environ.get("VIRUSTOTAL_API_KEY")
    gsb_key = args.gsb_key or os.environ.get("GOOGLE_SAFEBROWSING_KEY")

    banner()

    guard = PhishGuardPro(
        virustotal_api_key=vt_key,
        google_safebrowsing_key=gsb_key,
        enable_whois=not args.no_whois and not args.offline,
        enable_network=not args.offline,
        enable_http=not args.offline,
    )

    results = []

    if args.urls:
        for url in args.urls:
            result = guard.scan(url)
            results.append(result)
            if args.quiet:
                print(f"{result.raw_score:5.1f}/100  {result.phishing_probability*100:5.1f}%  "
                      f"{result.verdict_level.upper():<8}  {url}")
            elif args.json:
                print(result.to_json())
            else:
                render(result, verbose=args.verbose)

        if len(results) > 1 and not args.quiet and not args.json:
            bulk_summary(results)

    elif args.demo:
        results = run_demo(guard, verbose=args.verbose)

    else:
        run_interactive(guard, verbose=args.verbose)
        return

    # Exports
    if args.export_json and results:
        with open(args.export_json, "w") as f:
            json.dump({"generated": datetime.now().isoformat(),
                       "results": [r.to_dict() for r in results]},
                      f, indent=2, default=str)
        print(f"  ✓ JSON → {args.export_json}")

    if args.export_csv and results:
        import csv
        with open(args.export_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["URL","Domain","Score","Probability","Level","Verdict"])
            for r in results:
                w.writerow([r.url, r.registered_domain,
                             f"{r.raw_score:.1f}", f"{r.phishing_probability:.4f}",
                             r.verdict_level, r.verdict])
        print(f"  ✓ CSV → {args.export_csv}")


if __name__ == "__main__":
    main()
