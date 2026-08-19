from vulnscanner.models import Evidence, Finding, ScanResult, Severity


def test_scan_result_sorts_by_severity():
    result = ScanResult(target="https://example.com")
    result.add(Finding(severity=Severity.LOW, category="c", title="low", description="", url=""))
    result.add(Finding(severity=Severity.CRITICAL, category="c", title="crit", description="", url=""))
    result.add(Finding(severity=Severity.MEDIUM, category="c", title="med", description="", url=""))

    ordered = [f.title for f in result.sorted_findings()]
    assert ordered == ["crit", "med", "low"]


def test_counts_by_severity():
    result = ScanResult(target="https://example.com")
    result.add(Finding(severity=Severity.HIGH, category="c", title="a", description="", url=""))
    result.add(Finding(severity=Severity.HIGH, category="c", title="b", description="", url=""))
    counts = result.counts_by_severity()
    assert counts["HIGH"] == 2
    assert counts["CRITICAL"] == 0


def test_finding_as_dict_includes_evidence():
    f = Finding(
        severity=Severity.HIGH, category="XSS", title="t", description="d", url="https://x",
        evidence=Evidence(reasoning="because", matched_pattern="<script>"),
    )
    d = f.as_dict()
    assert d["severity"] == "HIGH"
    assert d["evidence"]["reasoning"] == "because"
    assert d["evidence"]["matched_pattern"] == "<script>"


def test_scan_result_as_dict_roundtrips():
    result = ScanResult(target="https://example.com")
    result.add(Finding(severity=Severity.INFO, category="c", title="t", description="", url=""))
    d = result.as_dict()
    assert d["target"] == "https://example.com"
    assert len(d["findings"]) == 1
