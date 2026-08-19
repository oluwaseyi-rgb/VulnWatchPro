"""Server/technology fingerprinting via response headers."""
from __future__ import annotations

from ..models import Evidence, Finding, Severity

CHECK_ID = "information-disclosure"

HEADERS_TO_CHECK = [
    "server", "x-powered-by", "x-aspnet-version",
    "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
]


def run(http_result, result) -> None:
    for h in HEADERS_TO_CHECK:
        val = http_result.headers.get(h) or http_result.headers.get(h.title())
        if val:
            result.add(Finding(
                severity=Severity.LOW,
                category="Information Disclosure",
                title=f"Technology disclosed via '{h}' header",
                description="The response reveals server/framework version information useful for "
                            "an attacker fingerprinting the stack.",
                url=http_result.url,
                evidence=Evidence(
                    request_url=http_result.url,
                    response_status=http_result.status_code,
                    matched_pattern=f"{h}: {val}",
                    reasoning=f"Header '{h}' is present with value '{val}'.",
                ),
                recommendation=f"Remove or generalize the '{h}' response header in server config.",
                check_id=CHECK_ID,
            ))
