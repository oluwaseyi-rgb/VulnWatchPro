# Changelog

## 2.0.0

Full rebuild from the original single-file `web_vuln_scanner.py`.

- Modular architecture: one file per concern (config, http client, DNS, TLS,
  auth, rate limiting, retries, logging, crawler, checks, reports).
- Every finding now carries structured `Evidence` (request/response detail,
  matched pattern, plain-English reasoning) instead of a bare description.
- Added: authentication support (basic/bearer/header/cookie), token-bucket
  rate limiting shared across threads, retry with exponential backoff on
  connection errors and configurable HTTP status codes, DNS pre-flight
  resolution and wildcard-DNS detection, redirect-chain inspection,
  structured/secret-redacting logging, config file + env var + CLI
  precedence, unit test suite.
- Reworked HTML report: collapsible evidence per finding, all evidence
  HTML-escaped (a captured XSS payload can no longer execute inside the
  report itself), request/response detail on click.
- SQLi check now diffs against a baseline (unmodified) request before
  flagging an error pattern, cutting false positives from pages that
  always contain SQL-error-like text.
- Sensitive-path checks require a content marker (not just HTTP 200) where
  false positives from catch-all 200 pages were likely.

## 1.0.0

Original single-file scanner (`web_vulnscanner.py`): security headers, SSL
checks, open redirects, basic reflected XSS/SQLi probing, directory
listing, sensitive path exposure, cookie flags, CORS, clickjacking, CSRF
token presence, HTML/JSON reporting.
