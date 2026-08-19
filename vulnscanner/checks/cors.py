"""CORS misconfiguration probing (active — sends a crafted Origin header)."""
from __future__ import annotations

from ..models import Evidence, Finding, Severity

CHECK_ID = "cors-misconfiguration"
EVIL_ORIGIN = "https://evil-cors-probe.example"


def run(url: str, client, result) -> None:
    r = client.get(url, headers={"Origin": EVIL_ORIGIN})
    if not r.ok:
        return

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*" and acac.lower() == "true":
        result.add(Finding(
            severity=Severity.HIGH,
            category="CORS",
            title="Wildcard CORS origin combined with credentials",
            description="The server sends Access-Control-Allow-Origin: * together with "
                         "Access-Control-Allow-Credentials: true, which browsers should reject but "
                         "some clients/proxies do not — a dangerous, spec-violating combination.",
            url=url,
            evidence=Evidence(
                request_method="GET", request_url=url,
                request_headers={"Origin": EVIL_ORIGIN},
                response_status=r.status_code,
                matched_pattern=f"ACAO={acao}; ACAC={acac}",
                reasoning="ACAO is exactly '*' and ACAC is 'true' in the same response.",
            ),
            recommendation="Never pair Access-Control-Allow-Origin: * with credentials; whitelist origins.",
            check_id=CHECK_ID,
        ))
    elif acao == EVIL_ORIGIN:
        sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
        result.add(Finding(
            severity=sev,
            category="CORS",
            title="CORS policy reflects arbitrary Origin",
            description="The server echoes back whatever Origin header it receives, including "
                         "origins it has never seen before, instead of validating against a whitelist.",
            url=url,
            evidence=Evidence(
                request_method="GET", request_url=url,
                request_headers={"Origin": EVIL_ORIGIN},
                response_status=r.status_code,
                matched_pattern=f"Sent Origin={EVIL_ORIGIN}; got ACAO={acao}",
                reasoning="Response ACAO exactly equals the arbitrary Origin we sent, which was never "
                          "whitelisted anywhere — i.e. it reflects any origin.",
            ),
            recommendation="Validate Origin against an explicit allow-list server-side; never reflect it verbatim.",
            check_id=CHECK_ID,
        ))
