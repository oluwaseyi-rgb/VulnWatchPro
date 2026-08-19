"""Clean, readable console summary — grouped by severity, evidence collapsed to one line."""
from __future__ import annotations

from ..models import ScanResult, Severity

COLORS = {
    "CRITICAL": "\033[97;41m",  # white on red
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "GREEN": "\033[92m",
    "DIM": "\033[2m",
}


def print_console_report(result: ScanResult) -> None:
    C = COLORS
    width = 72
    print()
    print(f"{C['BOLD']}{'═' * width}{C['RESET']}")
    print(f"{C['BOLD']}  VULNERABILITY SCAN REPORT{C['RESET']}")
    print(f"  Target : {result.target}")
    print(f"  Window : {result.start_time}  →  {result.end_time}")
    print(f"  Pages  : {len(result.scanned_urls)}   Requests: {result.stats.get('requests_made', '?')}"
          f"   Retries: {result.stats.get('retries', 0)}")
    print(f"{C['BOLD']}{'═' * width}{C['RESET']}")

    counts = result.counts_by_severity()
    print(f"\n{C['BOLD']}  Summary{C['RESET']}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = counts.get(sev, 0)
        bar = "█" * min(c, 40)
        print(f"    {C[sev]}{sev:<9}{C['RESET']} {c:>3}  {C[sev]}{bar}{C['RESET']}")

    findings = result.sorted_findings()
    if not findings:
        print(f"\n  {C['GREEN']}✓ No findings — clean scan.{C['RESET']}\n")
    else:
        print(f"\n{C['BOLD']}  Findings ({len(findings)}){C['RESET']}")
        print(f"  {'─' * (width - 2)}")
        for f in findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
            print(f"  {C[sev]}[{sev}]{C['RESET']} {f.title}")
            print(f"    {C['DIM']}category :{C['RESET']} {f.category}")
            print(f"    {C['DIM']}url      :{C['RESET']} {f.url}")
            if f.evidence and f.evidence.reasoning:
                print(f"    {C['DIM']}why      :{C['RESET']} {f.evidence.reasoning}")
            if f.recommendation:
                print(f"    {C['DIM']}fix      :{C['RESET']} {f.recommendation}")
            print()

    if result.errors:
        print(f"{C['BOLD']}  Errors ({len(result.errors)}){C['RESET']}")
        for e in result.errors[:20]:
            print(f"    {C['DIM']}- {e}{C['RESET']}")
        if len(result.errors) > 20:
            print(f"    {C['DIM']}... and {len(result.errors) - 20} more{C['RESET']}")

    print(f"{C['BOLD']}{'═' * width}{C['RESET']}\n")
