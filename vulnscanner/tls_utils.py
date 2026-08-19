"""
TLS/SSL configuration inspection: certificate validity/expiry, cipher
strength, protocol version, and hostname verification — each finding
carries the raw evidence (cert fields, cipher tuple) it was derived from.
"""
from __future__ import annotations

import logging
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone

from .models import Evidence, Finding, Severity

logger = logging.getLogger("vulnscanner.tls")

WEAK_CIPHER_MARKERS = ("RC4", "DES", "NULL", "EXPORT", "MD5", "3DES")
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_tls(target_url: str, result, timeout: float = 5.0, check_id: str = "tls") -> None:
    parsed = urllib.parse.urlparse(target_url)

    if parsed.scheme != "https":
        result.add(Finding(
            severity=Severity.HIGH,
            category="TLS",
            title="Site does not enforce HTTPS",
            description="The target was requested over plain HTTP; traffic is unencrypted.",
            url=target_url,
            evidence=Evidence(request_url=target_url, reasoning="URL scheme is 'http', not 'https'."),
            recommendation="Serve all traffic over HTTPS and redirect HTTP to HTTPS.",
            check_id=check_id,
        ))
        return

    host = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher_name, tls_version, _bits = ssock.cipher()
                proto = ssock.version()

                _check_expiry(cert, target_url, result, check_id)
                _check_cipher(cipher_name, target_url, result, check_id)
                _check_protocol(proto, target_url, result, check_id)

    except ssl.SSLCertVerificationError as exc:
        result.add(Finding(
            severity=Severity.HIGH,
            category="TLS",
            title="Certificate validation failed",
            description="The server's certificate could not be verified against trusted CAs.",
            url=target_url,
            evidence=Evidence(request_url=target_url, matched_pattern=str(exc),
                               reasoning="ssl module raised SSLCertVerificationError during handshake."),
            recommendation="Install a valid certificate from a trusted CA; check chain completeness.",
            check_id=check_id,
        ))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.errors.append(f"TLS check could not connect to {host}:{port}: {exc}")
    except Exception as exc:  # defensive: never let a TLS quirk crash the scan
        logger.debug("Unexpected TLS check error for %s: %s", target_url, exc)


def _check_expiry(cert: dict, url: str, result, check_id: str) -> None:
    expire_str = cert.get("notAfter", "") if cert else ""
    if not expire_str:
        return
    try:
        expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return
    days_left = (expire_dt - datetime.now(timezone.utc)).days

    if days_left < 0:
        result.add(Finding(
            severity=Severity.CRITICAL,
            category="TLS",
            title="Certificate has expired",
            description=f"The TLS certificate expired {abs(days_left)} day(s) ago.",
            url=url,
            evidence=Evidence(request_url=url, matched_pattern=f"notAfter={expire_str}",
                               reasoning="Certificate notAfter date is in the past relative to now (UTC)."),
            recommendation="Renew the certificate immediately.",
            check_id=check_id,
        ))
    elif days_left < 30:
        result.add(Finding(
            severity=Severity.HIGH,
            category="TLS",
            title="Certificate expiring soon",
            description=f"The TLS certificate expires in {days_left} day(s).",
            url=url,
            evidence=Evidence(request_url=url, matched_pattern=f"notAfter={expire_str}",
                               reasoning="Fewer than 30 days remain before certificate expiry."),
            recommendation="Renew the certificate ahead of expiry to avoid an outage.",
            check_id=check_id,
        ))


def _check_cipher(cipher_name: str, url: str, result, check_id: str) -> None:
    if cipher_name and any(w in cipher_name.upper() for w in WEAK_CIPHER_MARKERS):
        result.add(Finding(
            severity=Severity.HIGH,
            category="TLS",
            title=f"Weak cipher suite negotiated: {cipher_name}",
            description="The server negotiated a cipher suite with known weaknesses.",
            url=url,
            evidence=Evidence(request_url=url, matched_pattern=cipher_name,
                               reasoning=f"Cipher name contains a weak-cipher marker "
                                         f"({', '.join(w for w in WEAK_CIPHER_MARKERS if w in cipher_name.upper())})."),
            recommendation="Disable legacy ciphers server-side; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).",
            check_id=check_id,
        ))


def _check_protocol(proto: str, url: str, result, check_id: str) -> None:
    if proto in WEAK_PROTOCOLS:
        result.add(Finding(
            severity=Severity.HIGH,
            category="TLS",
            title=f"Outdated TLS protocol negotiated: {proto}",
            description="The server allowed negotiation of a deprecated TLS/SSL protocol version.",
            url=url,
            evidence=Evidence(request_url=url, matched_pattern=proto,
                               reasoning=f"Negotiated protocol '{proto}' is in the deprecated set {sorted(WEAK_PROTOCOLS)}."),
            recommendation="Disable protocols below TLS 1.2 (ideally require TLS 1.2+/1.3).",
            check_id=check_id,
        ))
