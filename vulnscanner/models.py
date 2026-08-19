"""
Core data models shared across the scanner: findings, evidence, and results.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]


@dataclass
class Evidence:
    """
    Concrete proof for *why* a finding was raised — not just "trust me".
    Every check should populate as much of this as is relevant so a human
    (or the report) can verify the claim independently.
    """
    request_method: str = ""
    request_url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    response_status: Optional[int] = None
    response_headers: dict = field(default_factory=dict)
    response_snippet: str = ""          # truncated, relevant slice of the body
    matched_pattern: str = ""           # regex / string that triggered the finding
    reasoning: str = ""                 # one-line plain-English "why this means X"
    timing_ms: Optional[float] = None

    def as_dict(self) -> dict:
        return {
            "request_method": self.request_method,
            "request_url": self.request_url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_snippet": self.response_snippet,
            "matched_pattern": self.matched_pattern,
            "reasoning": self.reasoning,
            "timing_ms": self.timing_ms,
        }


@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    description: str
    url: str
    evidence: Evidence = field(default_factory=Evidence)
    recommendation: str = ""
    confidence: str = "firm"            # tentative | firm | certain
    cwe: Optional[str] = None
    check_id: str = ""

    def as_dict(self) -> dict:
        return {
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence.as_dict(),
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "check_id": self.check_id,
        }


@dataclass
class ScanResult:
    target: str
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: str = ""
    findings: list = field(default_factory=list)
    scanned_urls: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)  # requests_made, retries, rate_limit_waits, etc.

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: f.severity.rank if isinstance(f.severity, Severity) else 99)

    def counts_by_severity(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "scanned_urls": self.scanned_urls,
            "errors": self.errors,
            "stats": self.stats,
            "findings": [f.as_dict() for f in self.sorted_findings()],
        }
