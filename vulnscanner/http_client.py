"""
HTTP client: a thin, instrumented wrapper around `requests.Session`.

Responsibilities:
  - connection pooling / keep-alive via a shared Session
  - rate limiting (shared TokenBucket across all threads)
  - retries with backoff on connection errors and configured status codes
  - manual redirect following so every hop can be inspected (evidence for
    open-redirect / mixed-content / downgrade findings)
  - consistent timing + structured result object (HttpResult) instead of
    raw `requests.Response` so callers get evidence-ready data
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry as _Urllib3Retry
except ImportError:  # pragma: no cover
    _Urllib3Retry = None

from .auth import apply_auth
from .config import ScanConfig
from .ratelimit import TokenBucket
from .retry import retry as retry_decorator

logger = logging.getLogger("vulnscanner.http")


@dataclass
class HttpResult:
    ok: bool
    method: str = ""
    url: str = ""
    status_code: Optional[int] = None
    headers: dict = field(default_factory=dict)
    text: str = ""
    cookies: dict = field(default_factory=dict)
    elapsed_ms: float = 0.0
    redirect_chain: list = field(default_factory=list)   # list of (url, status, location)
    error: Optional[str] = None
    request_headers: dict = field(default_factory=dict)


class HttpClient:
    def __init__(self, config: ScanConfig, stats: dict | None = None):
        self.config = config
        self.stats = stats if stats is not None else {}
        self.stats.setdefault("requests_made", 0)
        self.stats.setdefault("retries", 0)
        self.stats.setdefault("rate_limit_waits", 0)

        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self.session.headers.update({"User-Agent": config.user_agent, **config.extra_headers})
        if config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}

        # connection pooling tuned for concurrency
        adapter = HTTPAdapter(pool_connections=config.threads, pool_maxsize=config.threads * 2)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        apply_auth(self.session, config.auth, timeout=config.timeout)

        self.bucket = TokenBucket(config.rate_limit)

    # -- internal ---------------------------------------------------------

    def _should_retry_response(self, resp: Optional[requests.Response]) -> bool:
        return resp is not None and resp.status_code in self.config.retry_status_codes

    def _do_request(self, method: str, url: str, **kwargs) -> requests.Response:
        self.bucket.acquire()
        if self.config.delay:
            time.sleep(self.config.delay)
        self.stats["requests_made"] += 1

        def _on_retry(attempt, exc, result):
            self.stats["retries"] += 1
            logger.debug("retrying %s %s (attempt %d): %s", method, url, attempt + 1, exc or "bad status")

        decorated = retry_decorator(
            max_retries=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            exceptions=(requests.ConnectionError, requests.Timeout),
            should_retry_result=self._should_retry_response,
            on_retry=_on_retry,
        )(self.session.request)

        return decorated(method, url, timeout=self.config.timeout, allow_redirects=False, **kwargs)

    # -- public -------------------------------------------------------------

    def request(self, method: str, url: str, follow_redirects: Optional[bool] = None,
                **kwargs) -> HttpResult:
        follow = self.config.follow_redirects if follow_redirects is None else follow_redirects
        redirect_chain: list = []
        current_url = url
        start = time.monotonic()

        for hop in range(self.config.max_redirects + 1):
            try:
                resp = self._do_request(method, current_url, **kwargs)
            except (requests.ConnectionError, requests.Timeout) as exc:
                return HttpResult(ok=False, method=method, url=current_url, error=str(exc),
                                   redirect_chain=redirect_chain,
                                   elapsed_ms=(time.monotonic() - start) * 1000)
            except requests.RequestException as exc:
                return HttpResult(ok=False, method=method, url=current_url, error=str(exc),
                                   redirect_chain=redirect_chain,
                                   elapsed_ms=(time.monotonic() - start) * 1000)

            if resp.is_redirect and follow and hop < self.config.max_redirects:
                location = resp.headers.get("Location", "")
                redirect_chain.append((current_url, resp.status_code, location))
                current_url = requests.compat.urljoin(current_url, location)
                continue

            elapsed_ms = (time.monotonic() - start) * 1000
            return HttpResult(
                ok=True,
                method=method,
                url=resp.url if not redirect_chain else current_url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text if _looks_textual(resp) else "",
                cookies=resp.cookies.get_dict(),
                elapsed_ms=elapsed_ms,
                redirect_chain=redirect_chain,
                request_headers=dict(resp.request.headers) if resp.request else {},
            )

        return HttpResult(ok=False, method=method, url=current_url, error="too many redirects",
                           redirect_chain=redirect_chain, elapsed_ms=(time.monotonic() - start) * 1000)

    def get(self, url: str, **kwargs) -> HttpResult:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HttpResult:
        return self.request("POST", url, **kwargs)


def _looks_textual(resp: requests.Response) -> bool:
    ctype = resp.headers.get("Content-Type", "")
    if not ctype:
        return True
    return any(t in ctype for t in ("text", "json", "xml", "javascript", "html"))
