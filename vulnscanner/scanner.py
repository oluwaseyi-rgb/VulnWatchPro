"""
Orchestrates a full scan: DNS -> TLS -> host-level active checks -> crawl ->
per-page passive + active checks, using a bounded thread pool and a shared
rate-limited HTTP client throughout.
"""
from __future__ import annotations

import concurrent.futures
import logging
import time
import urllib.parse
from datetime import datetime, timezone

from . import checks
from .config import ScanConfig
from .crawler import extract_links
from .dns_utils import check_wildcard_dns, resolve
from .http_client import HttpClient
from .models import ScanResult
from .tls_utils import check_tls

logger = logging.getLogger("vulnscanner.scanner")


class Scanner:
    def __init__(self, config: ScanConfig):
        config.validate()
        self.config = config
        self.result = ScanResult(target=config.target.rstrip("/"))
        self.client = HttpClient(config, stats=self.result.stats)
        self._enabled_checks = self._resolve_enabled_checks()

    def _resolve_enabled_checks(self) -> dict:
        excluded = set(self.config.exclude_checks)
        enabled = {
            "passive": [c for c in checks.PASSIVE_CHECKS if c.CHECK_ID not in excluded],
            "active_page": [c for c in checks.ACTIVE_PAGE_CHECKS if c.CHECK_ID not in excluded],
            "active_host": [c for c in checks.ACTIVE_HOST_CHECKS if c.CHECK_ID not in excluded],
        }
        return enabled

    def run(self) -> ScanResult:
        target = self.result.target
        self.result.start_time = datetime.now(timezone.utc).isoformat()
        logger.info("Starting scan of %s (depth=%d, threads=%d, rate_limit=%s/s)",
                    target, self.config.depth, self.config.threads,
                    self.config.rate_limit or "unlimited")

        host = urllib.parse.urlparse(target).hostname
        logger.info("Resolving DNS for %s", host)
        dns_report = resolve(host, timeout=self.config.timeout)
        if dns_report.error:
            self.result.errors.append(f"DNS resolution failed for {host}: {dns_report.error}")
            logger.error("DNS resolution failed, aborting scan: %s", dns_report.error)
            self.result.end_time = datetime.now(timezone.utc).isoformat()
            return self.result
        logger.info("Resolved %s -> %s (%.1fms)", host, dns_report.resolved_ips, dns_report.resolution_time_ms)

        if check_wildcard_dns(host, timeout=self.config.timeout):
            logger.warning("Wildcard DNS detected on %s — subdomain-style findings may be unreliable", host)

        logger.info("Checking TLS/SSL configuration")
        check_tls(target, self.result, timeout=self.config.timeout)

        if self.config.include_active_checks:
            logger.info("Running host-level active checks (sensitive paths, dir listing, CORS)")
            for mod in self._enabled_checks["active_host"]:
                self._run_host_check(mod, target)

        self._crawl_and_check(target)

        self.result.end_time = datetime.now(timezone.utc).isoformat()
        logger.info("Scan complete: %d findings across %d page(s), %d request(s) made",
                    len(self.result.findings), len(self.result.scanned_urls),
                    self.result.stats.get("requests_made", 0))
        return self.result

    def _run_host_check(self, mod, target: str) -> None:
        try:
            if mod.__name__.endswith("sensitive_paths"):
                mod.run(target, self.client, self.result, threads=self.config.threads)
            else:
                mod.run(target, self.client, self.result)
        except Exception as exc:  # a single check must never abort the whole scan
            logger.exception("Host check %s failed: %s", mod.__name__, exc)
            self.result.errors.append(f"{mod.__name__} failed: {exc}")

    def _crawl_and_check(self, target: str) -> None:
        visited: set[str] = set()
        queue = [target]

        for current_depth in range(self.config.depth):
            if not queue or len(visited) >= self.config.max_pages:
                break
            next_queue: list[str] = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as ex:
                futures = {}
                for url in queue:
                    if url in visited or len(visited) >= self.config.max_pages:
                        continue
                    visited.add(url)
                    futures[ex.submit(self._scan_page, url)] = url

                for fut in concurrent.futures.as_completed(futures):
                    url = futures[fut]
                    try:
                        links = fut.result()
                        if current_depth < self.config.depth - 1:
                            next_queue.extend(links)
                    except Exception as exc:
                        logger.exception("Error scanning %s: %s", url, exc)
                        self.result.errors.append(f"{url}: {exc}")

            queue = [u for u in set(next_queue) if u not in visited]

    def _scan_page(self, url: str) -> list:
        logger.info("Scanning page: %s", url)
        r = self.client.get(url)
        if not r.ok:
            self.result.errors.append(f"Could not reach {url}: {r.error}")
            return []

        self.result.scanned_urls.append(url)

        for mod in self._enabled_checks["passive"]:
            try:
                mod.run(r, self.result)
            except Exception as exc:
                logger.exception("Passive check %s failed on %s: %s", mod.__name__, url, exc)
                self.result.errors.append(f"{mod.__name__} on {url}: {exc}")

        if self.config.include_active_checks:
            parsed = urllib.parse.urlparse(url)
            if urllib.parse.parse_qs(parsed.query):
                for mod in self._enabled_checks["active_page"]:
                    try:
                        mod.run(url, self.client, self.result)
                    except Exception as exc:
                        logger.exception("Active check %s failed on %s: %s", mod.__name__, url, exc)
                        self.result.errors.append(f"{mod.__name__} on {url}: {exc}")

        return extract_links(self.result.target, url, r.text)
