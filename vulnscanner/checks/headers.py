"""Missing / weak HTTP security headers."""
from __future__ import annotations

import re

from ..models import Evidence, Finding, Severity

CHECK_ID = "missing-security-headers"

SECURITY_HEADERS = {
    "Strict-Transport-Security": (Severity.HIGH,
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    "Content-Security-Policy": (Severity.MEDIUM,
        "Define a strict Content-Security-Policy to mitigate XSS and data injection."),
    "X-Content-Type-Options": (Severity.MEDIUM,
        "Add: X-Content-Type-Options: nosniff"),
    "X-Frame-Options": (Severity.MEDIUM,
        "Add: X-Frame-Options: DENY or SAMEORIGIN (also covered by CSP frame-ancestors)."),
    "Referrer-Policy": (Severity.LOW,
        "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy": (Severity.LOW,
        "Add a Permissions-Policy header to restrict browser feature access."),
}


def run(http_result, result) -> None:
    headers = {k.lower(): v for k, v in http_result.headers.items()}

    for header, (severity, recommendation) in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            result.add(Finding(
                severity=severity,
                category="Security Headers",
                title=f"Missing header: {header}",
                description=f"The response for this URL does not set the '{header}' header.",
                url=http_result.url,
                evidence=Evidence(
                    request_method=http_result.method,
                    request_url=http_result.url,
                    response_status=http_result.status_code,
                    response_headers=http_result.headers,
                    reasoning=f"'{header}' is absent from the response header set "
                              f"({len(headers)} headers received; case-insensitive match performed).",
                ),
                recommendation=recommendation,
                check_id=CHECK_ID,
            ))

    hsts = headers.get("strict-transport-security", "")
    if hsts:
        match = re.search(r"max-age=(\d+)", hsts)
        if match and int(match.group(1)) < 31536000:
            result.add(Finding(
                severity=Severity.LOW,
                category="Security Headers",
                title="HSTS max-age is too short",
                description="Strict-Transport-Security is present but max-age is under 1 year.",
                url=http_result.url,
                evidence=Evidence(
                    request_url=http_result.url,
                    response_status=http_result.status_code,
                    matched_pattern=hsts,
                    reasoning=f"Parsed max-age={match.group(1)} seconds, which is < 31536000 (1 year).",
                ),
                recommendation="Set max-age to at least 31536000 seconds.",
                check_id=CHECK_ID,
            ))
