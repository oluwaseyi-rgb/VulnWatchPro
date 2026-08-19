"""Machine-readable JSON report — same data as the HTML report."""
from __future__ import annotations

import json

from ..models import ScanResult


def generate_json_report(result: ScanResult, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result.as_dict(), fh, indent=2, default=str)
