"""Basic error-based SQL injection probing."""
from __future__ import annotations

import re
import urllib.parse

from ..models import Evidence, Finding, Severity

CHECK_ID = "sql-injection-error-based"

PAYLOADS = ["'", '"', "' OR '1'='1", '" OR "1"="1', "1' AND '1'='2"]

ERROR_PATTERNS = [
    r"sql syntax.{0,60}",
    r"mysql_fetch\w*",
    r"ORA-\d{5}",
    r"pg_query\(\).{0,60}",
    r"sqlite3?\.OperationalError",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Warning.{0,10}mysql_",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
]


def run(url: str, client, result) -> None:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return

    for param in params:
        baseline = client.get(url, params={k: v[0] for k, v in params.items()})
        for payload in PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = test_params[param] + payload
            r = client.get(url, params=test_params)
            if not r.ok:
                continue
            for pattern in ERROR_PATTERNS:
                m = re.search(pattern, r.text, re.IGNORECASE)
                if m and (not baseline.ok or m.group(0) not in baseline.text):
                    idx = m.start()
                    snippet = r.text[max(0, idx - 60):idx + len(m.group(0)) + 60]
                    result.add(Finding(
                        severity=Severity.CRITICAL,
                        category="SQL Injection",
                        title=f"Potential SQL injection in parameter '{param}'",
                        description=f"Appending a SQL metacharacter payload to '{param}' produced a "
                                     f"database error message that was absent from the baseline "
                                     f"(unmodified) request — a strong indicator of unsanitized input "
                                     f"reaching a SQL query.",
                        url=r.url,
                        evidence=Evidence(
                            request_method="GET", request_url=r.url,
                            response_status=r.status_code,
                            response_snippet=snippet,
                            matched_pattern=pattern,
                            reasoning=f"Regex '{pattern}' matched the response body for the "
                                      f"payload-modified request but not for the baseline request, "
                                      f"indicating the payload (not normal page content) caused it.",
                        ),
                        recommendation="Use parameterized queries / prepared statements; never "
                                       "concatenate user input into SQL. Add generic error pages.",
                        cwe="CWE-89",
                        check_id=CHECK_ID,
                    ))
                    break
            else:
                continue
            break  # one finding per param
