"""Probes for commonly-exposed sensitive files/paths (.git, .env, backups, admin panels)."""
from __future__ import annotations

import concurrent.futures
import urllib.parse

from ..models import Evidence, Finding, Severity

CHECK_ID = "sensitive-path-exposure"

# (path, severity, human label, optional substring that should appear in a
#  *real* positive to reduce false positives from custom 200-catchall pages)
SENSITIVE_PATHS = [
    ("/.git/HEAD", Severity.CRITICAL, "Git repository exposed", "ref:"),
    ("/.git/config", Severity.CRITICAL, "Git config exposed", "[core]"),
    ("/.svn/entries", Severity.HIGH, "SVN repository exposed", None),
    ("/.env", Severity.CRITICAL, "Environment file exposed", None),
    ("/.env.local", Severity.CRITICAL, "Environment file exposed", None),
    ("/.env.production", Severity.CRITICAL, "Environment file exposed", None),
    ("/config.php", Severity.HIGH, "PHP config file exposed", None),
    ("/wp-config.php", Severity.CRITICAL, "WordPress config exposed", None),
    ("/config.yml", Severity.HIGH, "YAML config exposed", None),
    ("/database.yml", Severity.HIGH, "Database config exposed", None),
    ("/backup.zip", Severity.HIGH, "Backup archive exposed", None),
    ("/backup.tar.gz", Severity.HIGH, "Backup archive exposed", None),
    ("/db_backup.sql", Severity.CRITICAL, "Database backup exposed", None),
    ("/dump.sql", Severity.CRITICAL, "Database dump exposed", None),
    ("/admin", Severity.MEDIUM, "Admin panel found", None),
    ("/phpmyadmin", Severity.HIGH, "phpMyAdmin exposed", None),
    ("/adminer.php", Severity.HIGH, "Adminer DB tool exposed", None),
    ("/error.log", Severity.HIGH, "Error log exposed", None),
    ("/access.log", Severity.HIGH, "Access log exposed", None),
    ("/server-status", Severity.MEDIUM, "Apache server-status exposed", "Apache Server Status"),
    ("/.htpasswd", Severity.CRITICAL, ".htpasswd file exposed", None),
    ("/robots.txt", Severity.INFO, "robots.txt found (review for hidden paths)", None),
]


def run(base_url: str, client, result, threads: int = 10) -> None:
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    def probe(entry):
        path, severity, label, must_contain = entry
        url = base + path
        r = client.get(url, follow_redirects=False)
        if not r.ok or r.status_code not in (200, 206):
            return
        if must_contain and must_contain.lower() not in r.text.lower():
            return  # likely a soft-404 / custom error page, not a real hit

        result.add(Finding(
            severity=severity,
            category="Sensitive File/Path Exposure",
            title=label,
            description=f"The path '{path}' returned HTTP {r.status_code} and is publicly reachable.",
            url=url,
            evidence=Evidence(
                request_method="GET", request_url=url,
                response_status=r.status_code,
                response_snippet=r.text[:300],
                matched_pattern=must_contain or f"HTTP {r.status_code}",
                reasoning=(f"Direct GET to '{path}' returned a 2xx status"
                           + (f" and contained the expected marker '{must_contain}'." if must_contain else ".")),
            ),
            recommendation=f"Restrict or remove public access to '{path}'.",
            check_id=CHECK_ID,
        ))
        result.scanned_urls.append(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(probe, SENSITIVE_PATHS))
