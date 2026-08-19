"""Directory listing exposure."""
from __future__ import annotations

import urllib.parse

from ..models import Evidence, Finding, Severity

CHECK_ID = "directory-listing"
TEST_PATHS = ["/images/", "/uploads/", "/static/", "/assets/", "/files/", "/backup/"]
MARKERS = ("index of /", "parent directory")


def run(base_url: str, client, result) -> None:
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in TEST_PATHS:
        url = base + path
        r = client.get(url)
        if not r.ok or r.status_code != 200 or not r.text:
            continue
        lower = r.text.lower()
        hit = next((m for m in MARKERS if m in lower), None)
        if hit:
            result.add(Finding(
                severity=Severity.MEDIUM,
                category="Directory Listing",
                title=f"Directory listing enabled at {path}",
                description="The web server auto-generates a browsable file listing for this directory.",
                url=url,
                evidence=Evidence(
                    request_method="GET", request_url=url,
                    response_status=r.status_code,
                    response_snippet=r.text[:300],
                    matched_pattern=hit,
                    reasoning=f"Response body contains the marker phrase '{hit}', typical of "
                              f"Apache/nginx autoindex output.",
                ),
                recommendation="Disable autoindex/directory listing in the web server configuration.",
                check_id=CHECK_ID,
            ))
