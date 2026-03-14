"""
PhishGuard PRO — Threat Intelligence Database
Comprehensive, research-backed data from real phishing datasets.
"""
import re

# ─────────────────────────────────────────────────────────────────────────────
# BRAND → OFFICIAL DOMAINS (60+ brands)
# ─────────────────────────────────────────────────────────────────────────────
BRAND_OFFICIAL_DOMAINS = {
    # Finance
    "paypal":         ["paypal.com", "paypal.me", "paypalobjects.com"],
    "stripe":         ["stripe.com", "stripe.network"],
    "chase":          ["chase.com", "jpmorganchase.com"],
    "bankofamerica":  ["bankofamerica.com", "bofa.com"],
    "wellsfargo":     ["wellsfargo.com"],
    "citibank":       ["citibank.com", "citi.com"],
    "hsbc":           ["hsbc.com", "hsbc.co.uk", "hsbc.in"],
    "barclays":       ["barclays.com", "barclays.co.uk"],
    "sbi":            ["sbi.co.in", "onlinesbi.sbi", "sbigeneral.in"],
    "icici":          ["icicibank.com", "icicidirect.com"],
    "hdfc":           ["hdfcbank.com", "hdfclife.com", "hdfcsec.com"],
    "axisbank":       ["axisbank.com"],
    "kotak":          ["kotak.com", "kotakbank.com", "kotaksecurities.com"],
    "paytm":          ["paytm.com", "paytmbank.com"],
    "phonepe":        ["phonepe.com"],
    "googlepay":      ["pay.google.com", "gpay.app"],
    "visa":           ["visa.com"],
    "mastercard":     ["mastercard.com", "mastercardservices.com"],
    "amex":           ["americanexpress.com", "aexp.com"],
    "rupay":          ["rupay.co.in", "npci.org.in"],
    "upi":            ["upi.npci.org.in", "bhimupi.org.in"],
    # Big Tech
    "google":         ["google.com","google.co.in","google.co.uk","google.ca",
                       "google.com.au","googleapis.com","goo.gl","google.de",
                       "google.fr","google.co.jp"],
    "apple":          ["apple.com","icloud.com","me.com","appleid.apple.com"],
    "microsoft":      ["microsoft.com","live.com","office.com","outlook.com",
                       "hotmail.com","bing.com","azure.com","msn.com",
                       "microsoftonline.com","office365.com","sharepoint.com"],
    "amazon":         ["amazon.com","amazon.in","amazon.co.uk","amazon.de",
                       "amazon.ca","amazonaws.com","amazon.com.au","amazon.fr",
                       "amazon.co.jp","amazon.es","amazon.it"],
    "meta":           ["meta.com","facebook.com","fb.com","instagram.com",
                       "whatsapp.com","oculus.com","threads.net"],
    "facebook":       ["facebook.com","fb.com","messenger.com","facebookmail.com"],
    "instagram":      ["instagram.com","cdninstagram.com"],
    "whatsapp":       ["whatsapp.com","whatsapp.net"],
    "twitter":        ["twitter.com","x.com","t.co","twimg.com"],
    "linkedin":       ["linkedin.com","lnkd.in","licdn.com"],
    "netflix":        ["netflix.com","nflxext.com","nflximg.net"],
    "spotify":        ["spotify.com","spotifycdn.com","scdn.co"],
    "adobe":          ["adobe.com","adobecc.com","adobesign.com","typekit.com"],
    "dropbox":        ["dropbox.com","dropboxusercontent.com","drop.sc"],
    "github":         ["github.com","githubusercontent.com","githubassets.com","github.io"],
    "gitlab":         ["gitlab.com","gitlab.io"],
    "slack":          ["slack.com","slack-edge.com","slack-files.com"],
    "zoom":           ["zoom.us","zoom.com","zoomgov.com"],
    "salesforce":     ["salesforce.com","force.com","salesforceliveagent.com"],
    "oracle":         ["oracle.com","oraclecloud.com"],
    # E-commerce
    "ebay":           ["ebay.com","ebay.co.uk","ebay.in","ebayimg.com"],
    "flipkart":       ["flipkart.com","fkcdn.com","flipkartimages.in"],
    "shopify":        ["shopify.com","myshopify.com","shopifycdn.com"],
    "alibaba":        ["alibaba.com","aliexpress.com","alipay.com","taobao.com"],
    "myntra":         ["myntra.com"],
    "swiggy":         ["swiggy.com"],
    "zomato":         ["zomato.com"],
    # Gaming
    "steam":          ["steampowered.com","steamcommunity.com","steamstatic.com"],
    "epic":           ["epicgames.com","fortnite.com","unrealengine.com"],
    "discord":        ["discord.com","discord.gg","discordapp.com","discordcdn.com"],
    "twitch":         ["twitch.tv","twitchapps.com","jtvnw.net"],
    "youtube":        ["youtube.com","youtu.be","ytimg.com","googlevideo.com"],
    "tiktok":         ["tiktok.com","tiktokcdn.com","tiktokv.com"],
    "snapchat":       ["snapchat.com","sc-cdn.net"],
    # Crypto
    "coinbase":       ["coinbase.com","coinbasepro.com"],
    "binance":        ["binance.com","binance.us","bnbchain.org"],
    "kraken":         ["kraken.com"],
    "blockchain":     ["blockchain.com","blockchain.info"],
    "metamask":       ["metamask.io"],
    "opensea":        ["opensea.io"],
    "uniswap":        ["uniswap.org","uniswap.exchange"],
    # Government / Logistics
    "irs":            ["irs.gov"],
    "usps":           ["usps.com"],
    "fedex":          ["fedex.com"],
    "dhl":            ["dhl.com","dhl.co.in","dhl.co.uk","dhl.de"],
    "ups":            ["ups.com"],
    "indiapost":      ["indiapost.gov.in","epostoffice.gov.in"],
    "incometax":      ["incometax.gov.in","efiling.incometax.gov.in"],
    "uidai":          ["uidai.gov.in"],
    "irctc":          ["irctc.co.in","irctcconnect.in"],
}

# Flat reverse map: domain → brand
DOMAIN_TO_BRAND = {}
for _brand, _domains in BRAND_OFFICIAL_DOMAINS.items():
    for _d in _domains:
        DOMAIN_TO_BRAND[_d] = _brand

ALL_BRAND_KEYWORDS = sorted(set(
    list(BRAND_OFFICIAL_DOMAINS.keys()) + [
        "wellsfargo", "bankofamerica", "americanexpress", "googleplay",
        "appstore", "icloud", "onedrive", "microsoft365", "office365",
        "amazonsupport", "amazonprime", "primevideo", "netflixsupport",
        "applestore", "appleid", "paypallogin", "facebooklogin",
        "instagramlogin", "whatsappweb", "telegramlogin",
    ]
), key=len, reverse=True)  # longest first to avoid partial matches


# ─────────────────────────────────────────────────────────────────────────────
# TLD RISK LEVELS  (source: Spamhaus, PhishTank research)
# ─────────────────────────────────────────────────────────────────────────────
CRITICAL_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom — #1 phishing TLDs
    ".top",                                # Extremely abused
}

HIGH_RISK_TLDS = {
    ".xyz", ".club", ".online", ".site", ".work", ".date", ".racing",
    ".win", ".bid", ".trade", ".stream", ".download", ".review",
    ".country", ".kim", ".science", ".party", ".gdn", ".loan",
    ".faith", ".men", ".accountant", ".click", ".link", ".pw",
    ".rest", ".bar", ".cam", ".icu", ".buzz", ".cyou", ".cfd",
    ".sbs", ".autos", ".boats", ".homes",
}

MEDIUM_RISK_TLDS = {
    ".info", ".biz", ".mobi", ".name", ".pro", ".tel",
}

# ─────────────────────────────────────────────────────────────────────────────
# URL SHORTENERS  (source: URLScan research)
# ─────────────────────────────────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "is.gd", "cli.gs", "tiny.cc", "url4.eu", "twit.ac",
    "su.pr", "tr.im", "short.to", "lnkd.in", "db.tt", "qr.ae",
    "aka.ms", "cutt.ly", "rb.gy", "shorturl.at", "snip.ly", "bl.ink",
    "rebrand.ly", "v.gd", "s.id", "linktr.ee", "lnk.to", "smarturl.it",
    "yourls.org", "trib.al", "ift.tt", "dlvr.it", "wp.me", "zpr.io",
    "x.co", "ito.mx", "clck.ru",
}

# ─────────────────────────────────────────────────────────────────────────────
# PHISHING KEYWORDS  (weighted by frequency in phishing datasets)
# ─────────────────────────────────────────────────────────────────────────────
KEYWORDS_CRITICAL = [
    "verify-your-account", "confirm-your-identity", "account-has-been-suspended",
    "unusual-sign-in", "we-detected-suspicious", "your-account-will-be-closed",
    "update-your-payment", "your-subscription-has-expired",
    "click-to-verify", "immediate-action-required",
]

KEYWORDS_HIGH = [
    "verify", "verification", "account-suspended", "account-locked",
    "account-disabled", "secure-login", "credential", "authenticate",
    "two-factor", "2fa", "reset-password", "password-reset",
    "confirm-email", "update-billing", "billing-issue", "payment-failed",
    "unusual-activity", "limited-access", "unauthorised", "unauthorized",
    "deactivate", "reactivate", "restore-access",
]

KEYWORDS_MEDIUM = [
    "login", "signin", "sign-in", "log-in", "verify", "account",
    "update", "confirm", "secure", "security", "banking", "wallet",
    "password", "validate", "suspend", "unlock", "recover",
    "recovery", "billing", "invoice", "payment", "urgent",
    "alert", "notice", "expire", "expired", "webscr",
]

KEYWORDS_LURE = [
    "free-gift", "winner", "prize", "reward", "bonus", "promo",
    "click-here", "congratulations", "you-won", "claim-now",
    "limited-time", "act-now", "survey", "cashback", "refund",
    "compensation", "lottery", "jackpot", "earn-money", "work-from-home",
    "investment", "crypto-profit", "double-your-bitcoin",
]

# ─────────────────────────────────────────────────────────────────────────────
# DANGEROUS EXTENSIONS
# ─────────────────────────────────────────────────────────────────────────────
DANGEROUS_EXTENSIONS = {
    ".exe": "Windows executable",
    ".bat": "Windows batch script",
    ".cmd": "Windows command script",
    ".ps1": "PowerShell script",
    ".vbs": "VBScript",
    ".js":  "JavaScript (standalone)",
    ".jar": "Java archive",
    ".scr": "Windows screensaver",
    ".msi": "Windows installer",
    ".apk": "Android package",
    ".dmg": "macOS disk image",
    ".hta": "HTML Application",
    ".pif": "Program info file",
    ".com": "MS-DOS executable",
    ".reg": "Windows registry",
    ".lnk": "Windows shortcut",
    ".iso": "Disk image",
    ".cab": "Windows cabinet",
    ".dll": "Dynamic link library",
    ".sys": "System driver",
}

# ─────────────────────────────────────────────────────────────────────────────
# LOOKALIKE / HOMOGLYPH MAPPING
# ─────────────────────────────────────────────────────────────────────────────
HOMOGLYPHS = {
    # Latin lookalikes
    "a": ["а","ａ","@","4","α","а"],  # Cyrillic а
    "b": ["ь","6","ƅ","Ь"],
    "c": ["с","ϲ","ć","ç"],            # Cyrillic с
    "d": ["ԁ","ď"],
    "e": ["е","ё","3","є","ε"],        # Cyrillic е
    "g": ["ɡ","9","ġ"],
    "h": ["ħ","н"],                    # Cyrillic н
    "i": ["і","і","1","l","ι","í"],   # Cyrillic і
    "k": ["κ","к"],                    # Cyrillic к
    "l": ["1","I","і","ι","ĺ"],
    "m": ["м","rn"],                   # Cyrillic м
    "n": ["п","η","ñ"],               # Cyrillic п
    "o": ["о","0","ο","ö","ó"],        # Cyrillic о
    "p": ["р","ρ"],                    # Cyrillic р
    "q": ["ԛ","զ"],
    "r": ["г","ŕ"],
    "s": ["ѕ","$","5","ś"],
    "t": ["τ","7","ţ"],
    "u": ["υ","ü","ú","μ"],
    "v": ["ν","υ"],
    "w": ["ω","vv"],
    "x": ["х","×"],                    # Cyrillic х
    "y": ["у","γ","ÿ"],               # Cyrillic у
    "z": ["ż","ź","2"],
}

# ─────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
PATTERN_IP       = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
PATTERN_HEX      = re.compile(r"%[0-9a-fA-F]{2}")
PATTERN_JS_INJECT= re.compile(r"(javascript:|vbscript:|data:text/html)", re.I)
PATTERN_PHISH_PATH = re.compile(
    r"/(wp-login|admin/login|webmail|cpanel|xmlrpc|phpmyadmin|"
    r"old/login|backup|\.env|config\.php|\.git/|vendor/|"
    r"composer\.json|\.htaccess|db\.php|eval-stdin)",
    re.I
)
PATTERN_REPEATED_CHARS = re.compile(r"(.)\1{4,}")   # 5+ same chars in a row

# ─────────────────────────────────────────────────────────────────────────────
# LEGIT ALEXA-STYLE TOP DOMAINS  (never flag these as phishing)
# ─────────────────────────────────────────────────────────────────────────────
WHITELIST_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "github.com", "reddit.com",
    "netflix.com", "microsoft.com", "apple.com", "yahoo.com", "bing.com",
    "stackoverflow.com", "office.com", "live.com", "outlook.com", "adobe.com",
    "dropbox.com", "zoom.us", "slack.com", "shopify.com", "paypal.com",
    "stripe.com", "cloudflare.com", "amazonaws.com", "googleapis.com",
    "github.io", "gitlab.com", "npmjs.com", "pypi.org", "docker.com",
    "heroku.com", "vercel.app", "netlify.app", "wordpress.com", "medium.com",
    "gov.in", "nic.in", "irctc.co.in", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "paytm.com", "flipkart.com",
}
