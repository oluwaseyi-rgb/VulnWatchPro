"""Cookie security attribute checks (Secure / HttpOnly / SameSite)."""
from __future__ import annotations

from ..models import Evidence, Finding, Severity

CHECK_ID = "insecure-cookies"


def run(http_result, result) -> None:
    set_cookie_headers = _get_set_cookie_headers(http_result.headers)

    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        lower = raw.lower()
        issues = []
        if "secure" not in lower:
            issues.append("missing Secure flag")
        if "httponly" not in lower:
            issues.append("missing HttpOnly flag")
        if "samesite" not in lower:
            issues.append("missing SameSite attribute")
        elif "samesite=none" in lower and "secure" not in lower:
            issues.append("SameSite=None without Secure flag")

        if issues:
            result.add(Finding(
                severity=Severity.MEDIUM,
                category="Cookie Security",
                title=f"Insecure cookie: {name}",
                description=f"Cookie '{name}' is missing recommended security attributes: "
                             f"{', '.join(issues)}.",
                url=http_result.url,
                evidence=Evidence(
                    request_url=http_result.url,
                    response_status=http_result.status_code,
                    matched_pattern=raw.split(";")[0] + "; ...",
                    reasoning=f"Set-Cookie header for '{name}' does not contain: {', '.join(issues)} "
                              f"(checked case-insensitively against the raw header).",
                ),
                recommendation="Set Secure, HttpOnly, and SameSite=Strict/Lax on all session/auth cookies.",
                check_id=CHECK_ID,
            ))


def _get_set_cookie_headers(headers: dict) -> list:
    # requests/urllib3 fold multiple Set-Cookie headers into one comma-joined
    # string in some paths; handle both a single string and a list.
    raw = headers.get("Set-Cookie") or headers.get("set-cookie")
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    # naive split on comma is unsafe (dates contain commas); split on
    # ", " followed by a token= pattern instead.
    import re
    parts = re.split(r",(?=\s*[\w!#$%&'*+.^_`|~-]+=)", raw)
    return [p.strip() for p in parts if p.strip()]
