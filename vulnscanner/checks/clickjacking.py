"""Clickjacking: absence of frame-busting headers."""
from __future__ import annotations

from ..models import Evidence, Finding, Severity

CHECK_ID = "clickjacking"


def run(http_result, result) -> None:
    headers = {k.lower(): v for k, v in http_result.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")

    protected = xfo.upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp.lower()
    if not protected:
        result.add(Finding(
            severity=Severity.MEDIUM,
            category="Clickjacking",
            title="Page can be framed by any origin",
            description="Neither X-Frame-Options nor a CSP frame-ancestors directive restricts framing, "
                         "so the page could be embedded in a malicious iframe for UI-redress attacks.",
            url=http_result.url,
            evidence=Evidence(
                request_url=http_result.url,
                response_status=http_result.status_code,
                matched_pattern=f"X-Frame-Options={xfo or '<absent>'}; CSP={csp or '<absent>'}",
                reasoning="X-Frame-Options is not DENY/SAMEORIGIN and CSP has no frame-ancestors directive.",
            ),
            recommendation="Set X-Frame-Options: DENY (or SAMEORIGIN) or add frame-ancestors to the CSP.",
            check_id=CHECK_ID,
        ))
