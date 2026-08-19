"""Command-line interface."""
from __future__ import annotations

import argparse
import sys

from .config import AuthConfig, ScanConfig
from .logging_setup import setup_logging
from .report import generate_html_report, generate_json_report, print_console_report
from .scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Modular web vulnerability scanner with evidence-backed findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnscan -u https://example.com
  vulnscan -u https://example.com --depth 2 -o report.html --json report.json
  vulnscan -u https://example.com --config scan.yaml
  vulnscan -u https://example.com --rate-limit 2 --threads 4 --no-active

Only scan systems you own or have explicit written permission to test.
Unauthorized scanning may be illegal.
        """,
    )
    parser.add_argument("-u", "--url", help="Target URL, e.g. https://example.com")
    parser.add_argument("-c", "--config", help="Path to a JSON/YAML config file")
    parser.add_argument("-o", "--output", default=None, help="HTML report path (default: scan_report.html)")
    parser.add_argument("--json", default=None, help="Also write a JSON report to this path")
    parser.add_argument("--depth", type=int, default=None, help="Crawl depth (default: 1)")
    parser.add_argument("--timeout", type=float, default=None, help="Per-request timeout in seconds")
    parser.add_argument("--delay", type=float, default=None, help="Fixed extra delay per request (seconds)")
    parser.add_argument("--rate-limit", type=float, default=None, dest="rate_limit",
                         help="Max requests/sec across all threads (0 = unlimited)")
    parser.add_argument("--threads", type=int, default=None, help="Concurrent worker threads")
    parser.add_argument("--max-retries", type=int, default=None, dest="max_retries")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--proxy", default=None, help="HTTP/S proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--user-agent", default=None, dest="user_agent")
    parser.add_argument("--no-active", action="store_true",
                         help="Disable intrusive active checks (XSS/SQLi/open-redirect/path probing)")
    parser.add_argument("--exclude-check", action="append", default=[], dest="exclude_checks",
                         help="Check ID to skip (repeatable), e.g. --exclude-check reflected-xss")
    parser.add_argument("--max-pages", type=int, default=None, dest="max_pages")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug-level logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Warnings/errors only")
    parser.add_argument("--log-file", default=None, dest="log_file")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("--auth-mode", choices=["none", "basic", "bearer", "header", "cookie"], default=None)
    auth.add_argument("--auth-username", default=None)
    auth.add_argument("--auth-password", default=None)
    auth.add_argument("--auth-token", default=None)
    auth.add_argument("--auth-header-name", default=None)
    auth.add_argument("--auth-header-value", default=None)
    auth.add_argument("--auth-login-url", default=None)

    return parser


def _build_config(args: argparse.Namespace) -> ScanConfig:
    config = ScanConfig.from_file(args.config) if args.config else ScanConfig()
    config.apply_env_overrides()

    overrides = {
        "target": args.url,
        "depth": args.depth,
        "timeout": args.timeout,
        "delay": args.delay,
        "rate_limit": args.rate_limit,
        "threads": args.threads,
        "max_retries": args.max_retries,
        "proxy": args.proxy,
        "user_agent": args.user_agent,
        "max_pages": args.max_pages,
        "log_file": args.log_file,
    }
    for key, val in overrides.items():
        if val is not None:
            setattr(config, key, val)

    if args.no_ssl_verify:
        config.verify_ssl = False
    if args.no_active:
        config.include_active_checks = False
    if args.exclude_checks:
        config.exclude_checks = tuple(set(config.exclude_checks) | set(args.exclude_checks))
    if args.output:
        config.output_html = args.output
    if args.json:
        config.output_json = args.json
    if args.verbose:
        config.log_level = "DEBUG"
    elif args.quiet:
        config.log_level = "WARNING"

    if args.auth_mode:
        config.auth = AuthConfig(
            mode=args.auth_mode,
            username=args.auth_username or "",
            password=args.auth_password or "",
            token=args.auth_token or "",
            header_name=args.auth_header_name or "",
            header_value=args.auth_header_value or "",
            login_url=args.auth_login_url or "",
        )

    if config.target and not config.target.startswith(("http://", "https://")):
        config.target = "https://" + config.target

    return config


def main(argv: list | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.url and not args.config:
        parser.error("either -u/--url or -c/--config (with a target set) is required")

    try:
        config = _build_config(args)
        config.validate()
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    logger = setup_logging(config.log_level, config.log_file)
    logger.debug("Effective config: %s", config.as_dict())

    try:
        scanner = Scanner(config)
        result = scanner.run()
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as exc:
        logger.exception("Scan failed: %s", exc)
        return 1

    print_console_report(result)
    generate_html_report(result, config.output_html)
    logger.info("HTML report written to %s", config.output_html)
    if config.output_json:
        generate_json_report(result, config.output_json)
        logger.info("JSON report written to %s", config.output_json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
