"""
Clean, readable HTML report.

Important: evidence snippets can contain raw attacker payloads (e.g. XSS
strings like <script>...</script>) captured from the target site. Everything
user/target-controlled is HTML-escaped before being embedded, so the report
itself can never become an XSS vector.
"""
from __future__ import annotations

import html
from collections import defaultdict

from ..models import ScanResult, Severity

SEVERITY_COLORS = {
    "CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#d4a017",
    "LOW": "#2e86c1", "INFO": "#7f8c8d",
}
SEVERITY_BG = {
    "CRITICAL": "#fdecea", "HIGH": "#fef2e6", "MEDIUM": "#fdf6e3",
    "LOW": "#eaf2fa", "INFO": "#f4f5f6",
}


def _esc(val) -> str:
    return html.escape(str(val), quote=True)


def _kv_rows(d: dict) -> str:
    if not d:
        return ""
    rows = "".join(f"<tr><td class='kv-k'>{_esc(k)}</td><td class='kv-v'>{_esc(v)}</td></tr>" for k, v in d.items())
    return f"<table class='kv-table'>{rows}</table>"


def _finding_html(f, idx: int) -> str:
    sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
    color = SEVERITY_COLORS.get(sev, "#999")
    bg = SEVERITY_BG.get(sev, "#fff")
    ev = f.evidence

    evidence_parts = []
    if ev.reasoning:
        evidence_parts.append(f"<p class='why'><strong>Why:</strong> {_esc(ev.reasoning)}</p>")
    if ev.request_method or ev.request_url:
        evidence_parts.append(
            f"<p><strong>Request:</strong> <code>{_esc(ev.request_method)} {_esc(ev.request_url)}</code></p>"
        )
    if ev.request_headers:
        evidence_parts.append(f"<details><summary>Request headers sent</summary>{_kv_rows(ev.request_headers)}</details>")
    if ev.response_status is not None:
        evidence_parts.append(f"<p><strong>Response status:</strong> <code>{ev.response_status}</code></p>")
    if ev.matched_pattern:
        evidence_parts.append(f"<p><strong>Matched:</strong> <code>{_esc(ev.matched_pattern)}</code></p>")
    if ev.response_snippet:
        evidence_parts.append(
            f"<details open><summary>Response snippet</summary><pre class='snippet'>{_esc(ev.response_snippet)}</pre></details>"
        )
    if ev.timing_ms is not None:
        evidence_parts.append(f"<p class='dim'>Timing: {ev.timing_ms:.1f}ms</p>")

    evidence_html = "".join(evidence_parts) or "<p class='dim'>No additional evidence captured.</p>"

    return f"""
    <div class="finding" style="border-left:4px solid {color};background:{bg};">
      <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
        <span class="badge" style="background:{color};">{_esc(sev)}</span>
        <span class="finding-title">{_esc(f.title)}</span>
        <span class="category-tag">{_esc(f.category)}</span>
        <span class="confidence-tag">{_esc(f.confidence)}</span>
        <span class="chevron">▸</span>
      </div>
      <div class="finding-body">
        <p><strong>URL:</strong> <code>{_esc(f.url)}</code></p>
        <p>{_esc(f.description)}</p>
        <div class="evidence-box">{evidence_html}</div>
        {"<p class='fix'><strong>Fix:</strong> " + _esc(f.recommendation) + "</p>" if f.recommendation else ""}
        {"<p class='dim'>" + _esc(f.cwe) + "</p>" if f.cwe else ""}
      </div>
    </div>"""


def generate_html_report(result: ScanResult, output_path: str) -> None:
    findings_sorted = result.sorted_findings()
    counts = result.counts_by_severity()

    finding_rows = "".join(_finding_html(f, i) for i, f in enumerate(findings_sorted, 1))
    scanned_list = "".join(f"<li><code>{_esc(u)}</code></li>" for u in result.scanned_urls) or "<li class='dim'>None</li>"
    error_list = "".join(f"<li>{_esc(e)}</li>" for e in result.errors) or "<li class='dim'>None</li>"

    summary_bars = ""
    max_count = max(counts.values()) or 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        width_pct = int((c / max_count) * 100) if max_count else 0
        summary_bars += f"""
        <div class="summary-item">
          <span class="summary-label" style="color:{color}">{sev}</span>
          <div class="summary-bar-wrap">
            <div class="summary-bar" style="width:{width_pct}%; background:{color};"></div>
          </div>
          <span class="summary-count">{c}</span>
        </div>"""

    stats = result.stats or {}
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Scan Report — {_esc(result.target)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, 'Segoe UI', system-ui, sans-serif; background: #f4f6f8; color: #1c2833; line-height: 1.5; }}
  .header {{ background: linear-gradient(135deg, #17202a 0%, #2c3e50 100%); color: white; padding: 36px 48px; }}
  .header h1 {{ font-size: 1.7rem; font-weight: 700; }}
  .header .subtitle {{ opacity: 0.7; margin-top: 6px; font-size: 0.9rem; }}
  .container {{ max-width: 980px; margin: 32px auto; padding: 0 20px 60px; }}
  .card {{ background: white; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 24px; overflow: hidden; }}
  .card-title {{ font-size: 1rem; font-weight: 700; padding: 16px 22px; border-bottom: 1px solid #eee; color: #2c3e50; }}
  .card-body {{ padding: 20px 22px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; }}
  .meta-item label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; color: #909497; }}
  .meta-item p {{ font-size: 0.9rem; font-weight: 600; margin-top: 3px; word-break: break-all; }}
  .summary-item {{ display: grid; grid-template-columns: 80px 1fr 30px; align-items: center; gap: 12px; margin-bottom: 10px; }}
  .summary-label {{ font-weight: 700; font-size: 0.8rem; }}
  .summary-bar-wrap {{ background: #eee; border-radius: 4px; height: 12px; overflow: hidden; }}
  .summary-bar {{ height: 100%; border-radius: 4px; }}
  .summary-count {{ font-weight: 700; font-size: 0.85rem; text-align: right; }}
  .finding {{ border-radius: 8px; margin-bottom: 12px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; padding: 12px 14px; flex-wrap: wrap; cursor: pointer; user-select: none; }}
  .badge {{ padding: 2px 9px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.3px; }}
  .finding-title {{ font-weight: 600; font-size: 0.92rem; flex: 1; min-width: 200px; }}
  .category-tag, .confidence-tag {{ font-size: 0.72rem; color: #7f8c8d; border: 1px solid #ddd; padding: 1px 8px; border-radius: 10px; background: rgba(255,255,255,0.6); }}
  .chevron {{ transition: transform 0.15s; color: #999; }}
  .finding.open .chevron {{ transform: rotate(90deg); }}
  .finding-body {{ display: none; padding: 4px 16px 16px; font-size: 0.87rem; }}
  .finding.open .finding-body {{ display: block; }}
  .finding-body p {{ margin: 6px 0; }}
  .why {{ background: rgba(0,0,0,0.04); padding: 8px 10px; border-radius: 6px; }}
  .evidence-box {{ margin-top: 8px; border-top: 1px dashed #ddd; padding-top: 8px; }}
  .fix {{ background: #eafaf1; padding: 8px 10px; border-radius: 6px; }}
  .dim {{ color: #909497; font-size: 0.8rem; }}
  code {{ background: rgba(0,0,0,0.06); padding: 1px 5px; border-radius: 3px; font-family: 'SF Mono', Consolas, monospace; font-size: 0.85em; word-break: break-all; }}
  pre.snippet {{ background: #1c2833; color: #d5dbdb; padding: 10px 12px; border-radius: 6px; overflow-x: auto; font-size: 0.78rem; white-space: pre-wrap; word-break: break-all; }}
  .kv-table {{ width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 0.8rem; }}
  .kv-table td {{ padding: 3px 6px; border-bottom: 1px solid #eee; }}
  .kv-k {{ color: #7f8c8d; width: 30%; }}
  details summary {{ cursor: pointer; font-size: 0.8rem; color: #2c3e50; font-weight: 600; margin-top: 6px; }}
  ul {{ padding-left: 20px; }}
  li {{ margin-bottom: 4px; }}
  .no-findings {{ text-align: center; padding: 36px; color: #27ae60; font-size: 1.05rem; font-weight: 700; }}
  .footer {{ text-align: center; padding: 24px; color: #909497; font-size: 0.8rem; }}
  .stat-row {{ display: flex; gap: 24px; flex-wrap: wrap; margin-top: 4px; font-size: 0.8rem; color: #7f8c8d; }}
</style>
</head>
<body>
<div class="header">
  <h1>Vulnerability Scan Report</h1>
  <div class="subtitle">{_esc(result.target)} · For authorized security testing only</div>
</div>
<div class="container">

  <div class="card">
    <div class="card-title">Scan Summary</div>
    <div class="card-body">
      <div class="meta-grid">
        <div class="meta-item"><label>Target</label><p>{_esc(result.target)}</p></div>
        <div class="meta-item"><label>Started</label><p>{_esc(result.start_time)}</p></div>
        <div class="meta-item"><label>Finished</label><p>{_esc(result.end_time)}</p></div>
        <div class="meta-item"><label>Pages Scanned</label><p>{len(result.scanned_urls)}</p></div>
        <div class="meta-item"><label>Total Findings</label><p>{len(result.findings)}</p></div>
      </div>
      <div class="stat-row">
        <span>Requests made: <strong>{stats.get('requests_made', '—')}</strong></span>
        <span>Retries: <strong>{stats.get('retries', 0)}</strong></span>
        <span>Rate-limit waits: <strong>{stats.get('rate_limit_waits', 0)}</strong></span>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Findings by Severity</div>
    <div class="card-body">{summary_bars}</div>
  </div>

  <div class="card">
    <div class="card-title">Findings ({len(result.findings)}) — click a row to expand evidence</div>
    <div class="card-body">
      {finding_rows if findings_sorted else '<div class="no-findings">✓ No vulnerabilities detected</div>'}
    </div>
  </div>

  <div class="card">
    <div class="card-title">Scanned URLs ({len(result.scanned_urls)})</div>
    <div class="card-body"><ul>{scanned_list}</ul></div>
  </div>

  <div class="card">
    <div class="card-title">Errors ({len(result.errors)})</div>
    <div class="card-body"><ul>{error_list}</ul></div>
  </div>

</div>
<div class="footer">
  This tool is for authorized security testing only. Unauthorized scanning may be illegal.
</div>
<script>
  // open CRITICAL/HIGH findings by default for visibility
  document.querySelectorAll('.finding').forEach(el => {{
    const badge = el.querySelector('.badge');
    if (badge && (badge.textContent === 'CRITICAL' || badge.textContent === 'HIGH')) {{
      el.classList.add('open');
    }}
  }});
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
