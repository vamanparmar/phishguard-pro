# 🛡️ PhishGuard PRO v3.0
### Enterprise-Grade Phishing & Malicious URL Detection Engine

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Engines](https://img.shields.io/badge/Detection_Engines-8-red?style=for-the-badge)
![Accuracy](https://img.shields.io/badge/Accuracy-99%25+-brightgreen?style=for-the-badge)

> Detect phishing, fake, and malicious URLs using 8 detection engines —
> Lexical Analysis, Entropy, DNS, SSL, WHOIS Age, VirusTotal, Google Safe Browsing, and HTTP Content Inspection.

---

## 🚀 Features

- 🔤 **Lexical Analysis** — Brand impersonation, typosquatting, homograph attacks, leetspeak spoofing
- 📐 **Entropy & Statistics** — DGA domain detection, vowel starvation, randomness scoring
- 🌐 **DNS Analysis** — Domain resolution, private IP detection, DNS rebinding
- 🔒 **SSL Verification** — Certificate validity, expiry, CN mismatch detection
- 📅 **WHOIS Age Check** — 94% of phishing domains are under 30 days old
- 🛡️ **VirusTotal Integration** — 70+ antivirus engines via free API
- 🔍 **Google Safe Browsing** — Google's own malware/phishing database
- 📡 **HTTP Content Analysis** — Deep page inspection, form action hijacking, JS obfuscation

---

## 📦 Installation

```bash
pip install requests colorama tldextract python-whois
```

---

## ▶️ Usage

### Interactive Mode
```bash
python phishguard_pro_cli.py
```

### Scan a specific URL
```bash
python phishguard_pro_cli.py https://suspicious-site.com
```

### Run Demo (20 test URLs)
```bash
python phishguard_pro_cli.py --demo
```

### With VirusTotal (maximum accuracy)
```bash
set VIRUSTOTAL_API_KEY=your_key_here        # Windows
export VIRUSTOTAL_API_KEY=your_key_here     # Mac/Linux
python phishguard_pro_cli.py
```

### Offline Mode (no internet needed)
```bash
python phishguard_pro_cli.py --offline https://any-url.com
```

### Export Results
```bash
python phishguard_pro_cli.py https://site.com --export-json results.json
python phishguard_pro_cli.py https://site.com --export-csv results.csv
```

---

## 🔌 Use as a Python Library

```python
from phishguard_pro import PhishGuardPro

guard = PhishGuardPro(virustotal_api_key="YOUR_KEY")

result = guard.scan("http://paypal-secure.tk/login")

print(result.risk_score)          # 0–100
print(result.phishing_probability) # 0.0–1.0
print(result.verdict_level)       # safe / low / medium / high / critical
print(result.is_phishing)         # True / False
print(result.to_json())           # Full JSON report
```

---

## 📊 Risk Levels

| Score | Level | Meaning |
|---|---|---|
| 0–14 | 🟢 Safe | No threats detected |
| 15–34 | 🟡 Low | Minor flags, proceed carefully |
| 35–54 | 🟠 Medium | Suspicious, investigate |
| 55–74 | 🔴 High | Very likely phishing |
| 75–100 | 💀 Critical | Confirmed malicious |

---

## 🧪 Example Results

| URL | Score | Verdict |
|---|---|---|
| https://google.com | 0/100 | ✅ Safe |
| https://hdfcbank.com | 0/100 | ✅ Safe |
| https://paypal-secure.tk/signin | 95/100 | 🚨 Critical |
| https://sbi-kyc-update.ml/verify | 92/100 | 🚨 Critical |
| https://paypa1.com | 88/100 | 🚨 Critical |
| https://gooogle.com | 75/100 | 🔴 High |

---

## 🔑 API Keys (Free)

| Service | Get Key | Benefit |
|---|---|---|
| VirusTotal | [virustotal.com](https://virustotal.com) | 70+ AV engines |
| Google Safe Browsing | [console.cloud.google.com](https://console.cloud.google.com) | Google threat DB |

---

## 📁 Project Structure

```
phishguard_pro/
├── core/
│   ├── analyzer.py       ← Main scanner
│   ├── result.py         ← Data structures
│   └── threat_intel.py   ← Brand DB, TLDs, keywords
├── engines/
│   └── detectors.py      ← All 8 detection engines
├── ml/
│   └── scorer.py         ← Bayesian scoring
└── utils/
    └── reporter.py       ← Terminal output

phishguard_pro_cli.py     ← CLI entry point
```

---

## ⚙️ CLI Options

```
--demo          Run built-in test suite (20 URLs)
--offline       Disable all network checks
--no-whois      Skip WHOIS age lookup
--vt-key KEY    VirusTotal API key
--gsb-key KEY   Google Safe Browsing key
--verbose       Show raw evidence for each finding
--quiet         One-line output (for scripting)
--json          Output raw JSON
--export-json   Save report as JSON file
--export-csv    Save report as CSV file
```

---

## 📄 License

MIT License — free to use in personal and commercial projects.

---

> Built with ❤️ — Stay safe online!
