"""
Modular vulnerability checks. Each module exposes a `run(...)` function with
a consistent signature so `scanner.py` can treat them uniformly and new
checks can be added without touching the orchestration code.

Passive checks run on a single already-fetched page (headers, cookies,
disclosure, clickjacking, CSRF-token presence).
Active checks issue their own probe requests (XSS, SQLi, open redirect,
sensitive paths, directory listing, CORS) and are gated behind
`config.include_active_checks` since they're intrusive.
"""
from . import (
    clickjacking,
    cookies,
    cors,
    csrf,
    directory_listing,
    headers,
    info_disclosure,
    open_redirect,
    sensitive_paths,
    sqli,
    xss,
)

PASSIVE_CHECKS = [headers, info_disclosure, cookies, clickjacking, csrf]
ACTIVE_PAGE_CHECKS = [xss, sqli, open_redirect]           # run per crawled URL with query params
ACTIVE_HOST_CHECKS = [sensitive_paths, directory_listing, cors]  # run once per host

__all__ = [
    "headers", "info_disclosure", "cookies", "clickjacking", "csrf",
    "xss", "sqli", "open_redirect", "sensitive_paths", "directory_listing", "cors",
    "PASSIVE_CHECKS", "ACTIVE_PAGE_CHECKS", "ACTIVE_HOST_CHECKS",
]
