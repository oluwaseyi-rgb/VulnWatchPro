from dataclasses import dataclass, field

from vulnscanner.checks import cookies, headers
from vulnscanner.models import ScanResult


@dataclass
class FakeHttpResult:
    url: str = "https://example.com/"
    method: str = "GET"
    status_code: int = 200
    headers: dict = field(default_factory=dict)
    text: str = ""


def test_headers_flags_missing_hsts_and_csp():
    result = ScanResult(target="https://example.com")
    r = FakeHttpResult(headers={"Content-Type": "text/html"})
    headers.run(r, result)
    titles = [f.title for f in result.findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


def test_headers_no_finding_when_all_present():
    result = ScanResult(target="https://example.com")
    r = FakeHttpResult(headers={
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    })
    headers.run(r, result)
    assert result.findings == []


def test_cookies_flags_missing_flags():
    result = ScanResult(target="https://example.com")
    r = FakeHttpResult(headers={"Set-Cookie": "session=abc123; Path=/"})
    cookies.run(r, result)
    assert len(result.findings) == 1
    assert "session" in result.findings[0].title


def test_cookies_no_finding_when_secure():
    result = ScanResult(target="https://example.com")
    r = FakeHttpResult(headers={"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"})
    cookies.run(r, result)
    assert result.findings == []
