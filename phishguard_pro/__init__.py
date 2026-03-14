"""
PhishGuard PRO v3.0 — Ultra-Accurate Phishing Detection
99%+ accuracy through multi-layer analysis + AI scoring
"""
from .core.analyzer import PhishGuardPro
from .core.result import ScanResult

__version__ = "3.0.0"
__all__ = ["PhishGuardPro", "ScanResult"]
