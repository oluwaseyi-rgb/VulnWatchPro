"""POST forms without a visible CSRF token."""
from __future__ import annotations

from ..models import Evidence, Finding, Severity

CHECK_ID = "csrf-missing-token"

CSRF_FIELD_NAMES = (
    "csrf_token", "csrftoken", "csrf-token", "_token",
    "authenticity_token", "__requestverificationtoken", "xsrf_token",
)


def run(http_result, result) -> None:
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return  # optional dependency; skip gracefully

    if not http_result.text:
        return

    try:
        soup = BeautifulSoup(http_result.text, "html.parser")
    except Exception:
        return

    forms = soup.find_all("form")
    for form in forms:
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue

        inputs = form.find_all("input")
        field_names = [(i.get("name") or "").lower() for i in inputs]
        has_named_token = any(name in CSRF_FIELD_NAMES for name in field_names)
        has_hidden_token = any(
            i.get("type", "").lower() == "hidden" and i.get("name")
            for i in inputs
        )

        if not (has_named_token or has_hidden_token):
            action = form.get("action") or http_result.url
            result.add(Finding(
                severity=Severity.MEDIUM,
                category="CSRF",
                title="POST form without an apparent CSRF token",
                description="A state-changing POST form was found with no CSRF-token-like hidden "
                             "field, suggesting it may be vulnerable to cross-site request forgery.",
                url=http_result.url,
                evidence=Evidence(
                    request_url=http_result.url,
                    response_status=http_result.status_code,
                    matched_pattern=f"<form method=post action='{action}'> field names: {field_names}",
                    reasoning=f"None of the form's input names match known CSRF field names "
                              f"{CSRF_FIELD_NAMES} and no hidden input with a name was found.",
                ),
                recommendation="Add a per-session CSRF token to the form and validate it server-side "
                               "(or rely on SameSite=Strict cookies plus origin checks).",
                check_id=CHECK_ID,
            ))
