"""
DNS resolution helpers used both to fail fast (target doesn't resolve) and
to feed a couple of low-severity informational/HIGH findings (wildcard DNS,
missing hosts, unexpectedly large TTL-less answer sets, etc).
"""
from __future__ import annotations

import logging
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("vulnscanner.dns")


@dataclass
class DnsReport:
    hostname: str
    resolved_ips: list = field(default_factory=list)
    resolution_time_ms: Optional[float] = None
    error: Optional[str] = None
    wildcard_dns: bool = False


def resolve(hostname: str, timeout: float = 5.0) -> DnsReport:
    report = DnsReport(hostname=hostname)
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    start = time.monotonic()
    try:
        infos = socket.getaddrinfo(hostname, None)
        report.resolved_ips = sorted({info[4][0] for info in infos})
    except socket.gaierror as exc:
        report.error = str(exc)
        logger.warning("DNS resolution failed for %s: %s", hostname, exc)
    finally:
        report.resolution_time_ms = (time.monotonic() - start) * 1000
        socket.setdefaulttimeout(old_timeout)
    return report


def check_wildcard_dns(hostname: str, timeout: float = 5.0) -> bool:
    """
    Resolves a random subdomain that should not exist. If it resolves anyway,
    the zone has a wildcard record, which affects subdomain-enumeration
    findings elsewhere (they become unreliable / need noting in the report).
    """
    probe = f"{uuid.uuid4().hex[:16]}.{hostname}"
    report = resolve(probe, timeout=timeout)
    return bool(report.resolved_ips)
