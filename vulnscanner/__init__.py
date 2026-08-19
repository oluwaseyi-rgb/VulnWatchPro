"""
vulnscanner — modular web vulnerability scanner with evidence-backed findings.
"""
from .config import AuthConfig, ScanConfig
from .models import Evidence, Finding, ScanResult, Severity
from .scanner import Scanner

__version__ = "2.0.0"

__all__ = [
    "ScanConfig", "AuthConfig", "Scanner",
    "ScanResult", "Finding", "Evidence", "Severity",
    "__version__",
]
