# vulnscanner

A modular, evidence-backed web vulnerability scanner. Every finding comes
with the request that triggered it, the response data that proves it, and a
one-line explanation of *why* it counts as a vulnerability — not just a
severity label.

```
$ vulnscanner -u https://example.com --depth 2

════════════════════════════════════════════════════════════════════
  VULNERABILITY SCAN REPORT
  Target : https://example.com
  Pages  : 12   Requests: 340   Retries: 2
════════════════════════════════════════════════════════════════════
  Summary
    CRITICAL   1  █
    HIGH       3  ███
    MEDIUM     5  █████
    LOW        2  ██
    INFO       4  ████

  Findings (15)
  ──────────────────────────────────────────────────────────────────
  [CRITICAL] Potential SQL injection in parameter 'id'
    category : SQL Injection
    url      : https://example.com/product?id=5'
    why      : Regex matched payload-modified request but not baseline.
    fix      : Use parameterized queries.
  ...
```

An HTML report is also generated with expandable, evidence-rich findings
(request/response headers, matched patterns, response snippets) — see
[`docs/sample-report.png`](#reports) below.

> ⚠️ **Only scan systems you own or have explicit written permission to
> test.** Unauthorized scanning may be illegal under laws such as the U.S.
> Computer Fraud and Abuse Act or the UK Computer Misuse Act.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Reports](#reports)
- [Testing](#testing)
- [Extending: adding a new check](#extending-adding-a-new-check)
- [Project layout](#project-layout)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features

Vulnerability checks:

- Missing/weak HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- TLS/SSL configuration: expired/expiring certs, weak ciphers, deprecated
  protocol versions, hostname verification failures
- Reflected XSS (payload-reflection based)
- Error-based SQL injection (baseline-diffed to cut false positives)
- Open redirect via common redirect-style parameters
- Directory listing exposure
- Sensitive file/path exposure (`.git`, `.env`, backups, admin panels, …)
- Cookie security flags (`Secure`, `HttpOnly`, `SameSite`)
- Server/technology information disclosure
- CORS misconfiguration (wildcard + credentials, arbitrary-origin reflection)
- Clickjacking (missing `X-Frame-Options` / `frame-ancestors`)
- CSRF token presence on POST forms

Engineering, not just checks:

| Concern | Implementation |
|---|---|
| **HTTP requests** | Shared `requests.Session` with connection pooling, consistent timeouts |
| **Concurrency** | Bounded `ThreadPoolExecutor` per crawl depth; thread-safe rate limiter |
| **DNS** | Pre-flight resolution (fail fast on `NXDOMAIN`), wildcard-DNS detection |
| **Redirects** | Manually followed hop-by-hop so each redirect is inspectable evidence |
| **TLS** | Direct `ssl` socket inspection: expiry, cipher strength, protocol version |
| **Response parsing** | Content-type-aware body handling, BeautifulSoup for HTML/forms |
| **Authentication** | Basic / Bearer / custom header / cookie-based login flow |
| **Rate limiting** | Token-bucket, shared across all worker threads |
| **Retries** | Exponential backoff + jitter, configurable status codes & exceptions |
| **Logging** | Structured, leveled logging with automatic secret redaction |
| **Configuration** | Defaults → config file (YAML/JSON) → env vars → CLI flags |
| **Error handling** | A failing check/page never aborts the scan; errors are collected and reported |
| **CLI design** | `argparse` with grouped flags, `--help`, config file support |
| **Testing** | `pytest` unit tests for rate limiter, retry logic, config, models, checks |
| **Modular architecture** | Each check is an independent module with a uniform `run()` signature |

## Architecture

```
                         ┌─────────────┐
                         │   cli.py    │  argparse → ScanConfig
                         └──────┬──────┘
                                ▼
                         ┌─────────────┐
                         │ scanner.py  │  orchestrates the whole run
                         └──────┬──────┘
              ┌─────────┬───────┼────────┬───────────┐
              ▼         ▼       ▼        ▼           ▼
         dns_utils  tls_utils  auth  http_client  crawler
                                         │
                                         ▼
                                 ┌───────────────┐
                                 │   checks/*    │  one module per vulnerability class
                                 └───────┬───────┘
                                         ▼
                                  models.ScanResult
                                         │
                              ┌──────────┼──────────┐
                              ▼          ▼          ▼
                          console.py  html_report  json_report
```

`http_client.HttpClient` is the single choke point every check goes through,
so rate limiting, retries, redirect handling, and auth are applied uniformly
no matter which check is calling it.

## Installation

```bash
git clone https://github.com/<your-username>/vulnscanner.git
cd vulnscanner
pip install -r requirements.txt
# or, as an installable CLI:
pip install -e .
```

Requires Python 3.9+.

## Usage

```bash
# Basic scan
vulnscan -u https://example.com

# Deeper crawl, custom output paths
vulnscan -u https://example.com --depth 3 -o report.html --json report.json

# Passive-only (no XSS/SQLi/path probing — safe for a quick recon pass)
vulnscan -u https://example.com --no-active

# Throttled, single-threaded, for a fragile staging target
vulnscan -u https://example.com --rate-limit 1 --threads 1

# Behind an auth wall (cookie-based session)
vulnscan -u https://example.com \
  --auth-mode cookie \
  --auth-login-url https://example.com/login

# From a config file (see config.example.yaml)
vulnscan -c config.example.yaml -u https://example.com

# Skip specific checks
vulnscan -u https://example.com --exclude-check reflected-xss --exclude-check sql-injection-error-based
```

Run without installing:

```bash
python web_vuln_scanner.py -u https://example.com
```

Full flag reference: `vulnscan --help`.

## Configuration

Precedence, highest wins: **CLI flags → environment variables (`VULNSCAN_*`)
→ config file → built-in defaults.**

See [`config.example.yaml`](config.example.yaml) for every available option.
Any field can also be set via environment variable, e.g.:

```bash
export VULNSCAN_RATE_LIMIT=2
export VULNSCAN_THREADS=4
export VULNSCAN_VERIFY_SSL=false
```

## Authentication

| Mode | What it does |
|---|---|
| `none` | No authentication (default) |
| `basic` | HTTP Basic auth (`--auth-username` / `--auth-password`) |
| `bearer` | `Authorization: Bearer <token>` (`--auth-token`) |
| `header` | Arbitrary header, e.g. an API key (`--auth-header-name` / `--auth-header-value`) |
| `cookie` | POSTs credentials to `--auth-login-url`, reuses the resulting session cookie for the rest of the scan |

Secrets are never written to logs or reports — the logging layer redacts
`Authorization`, `Cookie`, `password`, and `token` on the way out, and the
config dump used in reports redacts them too.

## Reports

Every run produces:

- A **console report** — colorized, grouped by severity, one-line evidence
  per finding, meant to be read directly in the terminal.
- An **HTML report** (`--output` / default `scan_report.html`) — click any
  finding to expand full evidence: the exact request made, response status,
  matched pattern/regex, and a response snippet. Critical/High findings are
  expanded by default. All evidence is HTML-escaped, so a payload the
  scanner captured (e.g. a raw `<script>` tag) is displayed safely rather
  than executed.
- An optional **JSON report** (`--json`) with the same data, for piping into
  other tooling or CI.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

The suite covers the rate limiter, retry/backoff logic, configuration
precedence and validation, the data models, and representative check
modules (using fake HTTP responses — no network access required).

## Extending: adding a new check

1. Create `vulnscanner/checks/my_check.py` with a module-level `CHECK_ID`
   and a `run(...)` function:
   - Passive checks: `run(http_result, result)`
   - Active per-page checks: `run(url, client, result)`
   - Active host-level checks: `run(base_url, client, result)`
2. Populate an `Evidence` object with whatever proves the finding
   (`matched_pattern`, `response_snippet`, `reasoning`, etc.) — the report
   is only as useful as the evidence you give it.
3. Register the module in `vulnscanner/checks/__init__.py` under the
   appropriate list (`PASSIVE_CHECKS`, `ACTIVE_PAGE_CHECKS`, `ACTIVE_HOST_CHECKS`).
4. Add a unit test in `tests/test_checks.py` using a fake result object —
   no live target required.

## Project layout

```
vulnscanner/
├── vulnscanner/
│   ├── cli.py              CLI entry point
│   ├── config.py           ScanConfig / AuthConfig, file+env+CLI precedence
│   ├── scanner.py          Orchestrates DNS → TLS → crawl → checks
│   ├── http_client.py      Rate-limited, retrying, redirect-aware HTTP layer
│   ├── auth.py             Basic/Bearer/header/cookie authentication
│   ├── dns_utils.py        Resolution + wildcard-DNS detection
│   ├── tls_utils.py        Certificate/cipher/protocol inspection
│   ├── crawler.py          Same-origin link extraction
│   ├── ratelimit.py        Thread-safe token bucket
│   ├── retry.py            Backoff+jitter retry decorator
│   ├── logging_setup.py    Structured, secret-redacting logging
│   ├── models.py           Finding / Evidence / ScanResult
│   ├── checks/             One module per vulnerability class
│   └── report/             Console, HTML, and JSON report generators
├── tests/                  pytest unit tests
├── config.example.yaml
├── web_vuln_scanner.py     Zero-install launcher
├── requirements.txt / requirements-dev.txt
├── pyproject.toml
└── README.md
```

## Disclaimer

This tool sends live HTTP requests — including intentionally malformed
ones designed to trigger errors (SQLi payloads, XSS payloads, path
traversal probes) — to the target. **Only run it against systems you own
or are explicitly authorized to test** (e.g. your own infrastructure, or a
program you're enrolled in on HackerOne/Bugcrowd/Intigriti whose scope
permits automated scanning). Use `--no-active` for a read-only, passive
pass if you're unsure a target permits active probing.

## License

MIT — see [LICENSE](LICENSE).
