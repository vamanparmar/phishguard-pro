"""
PhishGuard PRO Terminal Reporter
"""
from ..core.result import ScanResult

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    C = True
except ImportError:
    C = False

def _c(code, t): return (code + t + Style.RESET_ALL) if C else t
def RED(t):     return _c(Fore.RED + Style.BRIGHT, t)
def GREEN(t):   return _c(Fore.GREEN + Style.BRIGHT, t)
def YELLOW(t):  return _c(Fore.YELLOW + Style.BRIGHT, t)
def CYAN(t):    return _c(Fore.CYAN + Style.BRIGHT, t)
def MAGENTA(t): return _c(Fore.MAGENTA + Style.BRIGHT, t)
def WHITE(t):   return _c(Fore.WHITE + Style.BRIGHT, t)
def BLUE(t):    return _c(Fore.BLUE + Style.BRIGHT, t)
def DIM(t):     return _c(Style.DIM, t)

SEV_FN  = {"critical":RED,"high":YELLOW,"medium":lambda t:_c(Fore.YELLOW,t),
           "low":lambda t:_c(Fore.CYAN,t),"info":DIM}
SEV_ICO = {"critical":"💀","high":"🔴","medium":"🟡","low":"🔵","info":"  "}
VERD_FN = {"critical":RED,"high":RED,"medium":YELLOW,"low":YELLOW,"safe":GREEN}

ENGINE_LABELS = {
    "lexical":    "🔤  LEXICAL ANALYSIS",
    "entropy":    "📐  ENTROPY & STATISTICAL",
    "network":    "🌐  NETWORK (DNS/SSL/WHOIS)",
    "http":       "📡  HTTP CONTENT ANALYSIS",
    "reputation": "🛡   REPUTATION (VT/GSB)",
}


def banner():
    b = r"""
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗     ██████╗ ██████╗  ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║    ██████╔╝██████╔╝██║   ██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║    ██╔═══╝ ██╔══██╗██║   ██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝    ██║     ██║  ██║╚██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ """
    print(CYAN(b) if C else b)
    print(WHITE("  v3.0  ·  8 Detection Engines  ·  Entropy  ·  WHOIS  ·  VirusTotal  ·  ML Scoring"))
    print(DIM("  Lexical · Typosquat · Homograph · DGA · SSL · DNS · HTTP Content · Brand DB"))
    print()


def render(result: ScanResult, verbose: bool = False):
    W = 76

    print("\n" + "═"*W)
    print(WHITE("  PHISHGUARD PRO SCAN REPORT"))
    print("─"*W)
    print(f"  {'URL':<18} {result.url[:60]}")
    print(f"  {'Domain':<18} {result.domain}")
    print(f"  {'Reg. Domain':<18} {result.registered_domain}")
    if result.subdomain:
        print(f"  {'Subdomain':<18} {result.subdomain}")
    print(f"  {'TLD':<18} {result.tld}")
    if result.resolved_ip:
        print(f"  {'Resolved IP':<18} {result.resolved_ip}")
    if result.whois_age_days is not None:
        age_str = f"{result.whois_age_days} days ({result.whois_age_days//365}y)"
        print(f"  {'Domain Age':<18} {age_str}")
    if result.virustotal_positives is not None:
        vt_str = f"{result.virustotal_positives}/{result.virustotal_total} vendors flagged"
        fn = RED if result.virustotal_positives > 0 else GREEN
        print(f"  {'VirusTotal':<18} {fn(vt_str)}")
    if result.final_url and result.final_url != result.normalized_url:
        print(f"  {'Final URL':<18} {result.final_url[:60]}")
    print(f"  {'Scanned':<18} {result.timestamp}")
    print("─"*W)

    # Per-engine breakdown
    print(f"\n  {'ENGINE':<30} {'SCORE':>8}  {'STATUS'}")
    print("  " + "─"*60)

    score_map = {
        "lexical": result.lexical_score,
        "entropy": result.entropy_score,
        "network": result.network_score,
        "http":    result.http_score,
    }
    for eng, label in ENGINE_LABELS.items():
        score = score_map.get(eng, 0.0)
        bar = _score_bar(score, 15)
        if score >= 65:   sfn = RED
        elif score >= 35: sfn = YELLOW
        else:             sfn = GREEN
        print(f"  {label:<30} {sfn(f'{score:5.1f}/100')}  {bar}")

    print("─"*W)

    # Findings by engine
    engines_present = list(dict.fromkeys(c.engine for c in result.checks))
    for eng in engines_present:
        eng_checks = [c for c in result.checks if c.engine == eng]
        failures = sorted([c for c in eng_checks if not c.passed],
                          key=lambda c: c.weight, reverse=True)
        passes   = [c for c in eng_checks if c.passed]

        if not failures and not passes:
            continue

        label = ENGINE_LABELS.get(eng, eng.upper())
        print(f"\n  {CYAN(label)}")
        print("  " + "─"*60)

        for check in failures:
            icon = SEV_ICO.get(check.severity, " ")
            sfn  = SEV_FN.get(check.severity, str)
            sev_label = sfn(f"[{check.severity.upper()[:8]:8}]")
            print(f"  {icon} {sev_label} {WHITE(check.name)}")
            print(f"       {DIM('→')} {check.detail[:75]}")
            if verbose and check.evidence is not None:
                print(f"       {DIM('⚙')} {DIM(str(check.evidence)[:70])}")

        if passes:
            ok_names = ", ".join(c.name for c in passes[:6])
            more = f" (+{len(passes)-6} more)" if len(passes) > 6 else ""
            print(f"  {GREEN('  ✓')} {DIM(ok_names + more)}")

    # ── Final verdict block ──────────────────────────────────────────────────
    print("\n" + "═"*W)
    vfn = VERD_FN.get(result.verdict_level, str)

    score = result.raw_score
    filled = int(score / 5)
    bar = _score_bar(score, 20)

    print(f"  RISK SCORE       {vfn(f'{score:.1f}/100')}  {bar}")
    print(f"  PROBABILITY      {vfn(f'{result.phishing_probability*100:.1f}% phishing probability')}")
    print(f"  CONFIDENCE       {result.confidence:.0f}% confidence in verdict")
    print(f"  VERDICT          {vfn(result.verdict)}")

    if result.summary:
        print(f"\n  {MAGENTA('⚡ KEY FINDINGS:')}")
        for s in result.summary[:5]:
            print(f"  {DIM('•')} {s[:75]}")

    print("═"*W + "\n")


def _score_bar(score: float, width: int = 20) -> str:
    filled = int(score / 100 * width)
    empty  = width - filled
    if score >= 65:   fn = RED
    elif score >= 35: fn = YELLOW
    else:             fn = GREEN
    bar = fn("█" * filled) + DIM("░" * empty)
    return f"[{bar}]"


def bulk_summary(results: list):
    W = 80
    print("\n" + "═"*W)
    print(WHITE("  BULK SCAN SUMMARY"))
    print("─"*W)
    print(f"  {'#':<4} {'SCORE':<10} {'PROB':<8} {'LEVEL':<10} URL")
    print("─"*W)
    for i, r in enumerate(results, 1):
        vfn = VERD_FN.get(r.verdict_level, str)
        score_s = vfn(f"{r.raw_score:5.1f}/100")
        prob_s  = vfn(f"{r.phishing_probability*100:4.1f}%")
        lvl_s   = {"critical":RED("CRITICAL"),"high":RED("HIGH    "),
                   "medium":YELLOW("MEDIUM  "),"low":YELLOW("LOW     "),
                   "safe":GREEN("SAFE    ")}.get(r.verdict_level, r.verdict_level)
        url_s   = r.url[:48] + "..." if len(r.url) > 48 else r.url
        print(f"  {i:<4} {score_s}  {prob_s}  {lvl_s}  {url_s}")
    print("─"*W)
    safe  = sum(1 for r in results if r.verdict_level == "safe")
    risky = len(results) - safe
    print(f"  Total: {len(results)} | {GREEN(str(safe)+' safe')} | {RED(str(risky)+' suspicious/malicious')}")
    print("═"*W + "\n")
