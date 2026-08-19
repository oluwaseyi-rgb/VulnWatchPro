"""Basic reflected XSS detection via payload reflection in the response body."""
from __future__ import annotations

import urllib.parse

from ..models import Evidence, Finding, Severity

CHECK_ID = "reflected-xss"

PAYLOADS = [
    "<script>alert('vscan1')</script>",
    "\"><script>alert('vscan2')</script>",
    "'><img src=x onerror=alert('vscan3')>",
    "<svg onload=alert('vscan4')>",
]


def run(url: str, client, result) -> None:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return

    for param in params:
        for payload in PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            r = client.get(url, params=test_params)
            if not r.ok:
                continue
            if payload in r.text:
                idx = r.text.find(payload)
                snippet = r.text[max(0, idx - 60):idx + len(payload) + 60]
                result.add(Finding(
                    severity=Severity.HIGH,
                    category="Cross-Site Scripting (XSS)",
                    title=f"Potential reflected XSS in parameter '{param}'",
                    description=f"The parameter '{param}' is reflected in the response body "
                                 f"without apparent encoding, using a payload containing live HTML/JS.",
                    url=r.url,
                    evidence=Evidence(
                        request_method="GET", request_url=r.url,
                        response_status=r.status_code,
                        response_snippet=snippet,
                        matched_pattern=payload,
                        reasoning=f"The exact injected payload string appears verbatim in the "
                                  f"response body — it was not HTML-escaped, so a browser would "
                                  f"execute it.",
                    ),
                    recommendation="HTML-encode all user-controlled output; add a strict CSP; "
                                   "validate/allow-list input server-side.",
                    confidence="tentative",
                    cwe="CWE-79",
                    check_id=CHECK_ID,
                ))
                break  # one confirmed finding per parameter is enough
