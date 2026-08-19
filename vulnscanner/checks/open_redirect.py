"""Open redirect detection via known redirect-style parameters."""
from __future__ import annotations

import urllib.parse

from ..models import Evidence, Finding, Severity

CHECK_ID = "open-redirect"

REDIRECT_PARAMS = {
    "redirect", "redirect_to", "redirect_url", "return", "return_url",
    "returnurl", "next", "url", "goto", "target", "link", "forward", "continue",
}

EVIL_HOST = "evil-redirect-probe.example"
PAYLOADS = [f"https://{EVIL_HOST}", f"//{EVIL_HOST}", f"/\\{EVIL_HOST}"]


def run(url: str, client, result) -> None:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    candidates = [p for p in params if p.lower() in REDIRECT_PARAMS]
    if not candidates:
        return

    for param in candidates:
        for payload in PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            r = client.get(url, params=test_params, follow_redirects=False)
            if not r.ok or r.status_code not in (301, 302, 303, 307, 308):
                continue
            location = r.headers.get("Location", "")
            if EVIL_HOST in location:
                result.add(Finding(
                    severity=Severity.HIGH,
                    category="Open Redirect",
                    title=f"Open redirect via parameter '{param}'",
                    description=f"Setting '{param}' to an attacker-controlled URL causes the server "
                                 f"to issue a redirect to that external host, which can be abused for "
                                 f"phishing.",
                    url=r.url,
                    evidence=Evidence(
                        request_method="GET", request_url=r.url,
                        response_status=r.status_code,
                        response_headers={"Location": location},
                        matched_pattern=payload,
                        reasoning=f"Sent {param}={payload}; response was HTTP {r.status_code} with "
                                  f"Location header containing our attacker host '{EVIL_HOST}'.",
                    ),
                    recommendation="Validate redirect targets against an allow-list of relative paths "
                                   "or known-good hosts; never redirect to a raw user-supplied URL.",
                    cwe="CWE-601",
                    check_id=CHECK_ID,
                ))
                break
