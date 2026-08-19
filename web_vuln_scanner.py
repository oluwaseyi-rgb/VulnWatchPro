#!/usr/bin/env python3
"""Thin launcher so the tool can be run as `python web_vuln_scanner.py ...`
without installing the package."""
from vulnscanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
