"""
Authentication handling so the scanner can crawl/test pages that sit behind
a login instead of only ever seeing a login screen.

Supported modes:
  none    - unauthenticated
  basic   - HTTP Basic auth
  bearer  - Authorization: Bearer <token>
  header  - arbitrary custom header (e.g. an API key)
  cookie  - POST credentials to a login URL and reuse the resulting session
            cookie for the rest of the scan
"""
from __future__ import annotations

import logging

import requests

from .config import AuthConfig

logger = logging.getLogger("vulnscanner.auth")


class AuthError(RuntimeError):
    pass


def apply_auth(session: requests.Session, auth: AuthConfig, timeout: float = 10.0) -> None:
    if auth.mode == "none":
        return

    if auth.mode == "basic":
        session.auth = (auth.username, auth.password)

    elif auth.mode == "bearer":
        if not auth.token:
            raise AuthError("auth mode 'bearer' requires a token")
        session.headers["Authorization"] = f"Bearer {auth.token}"

    elif auth.mode == "header":
        if not auth.header_name:
            raise AuthError("auth mode 'header' requires header_name")
        session.headers[auth.header_name] = auth.header_value

    elif auth.mode == "cookie":
        if not auth.login_url:
            raise AuthError("auth mode 'cookie' requires login_url")
        try:
            resp = session.post(auth.login_url, data=auth.login_data, timeout=timeout)
        except requests.RequestException as exc:
            raise AuthError(f"login request failed: {exc}") from exc

        if auth.cookie_name and auth.cookie_name not in session.cookies:
            raise AuthError(
                f"login completed (HTTP {resp.status_code}) but expected cookie "
                f"'{auth.cookie_name}' was not set — check login_data/selectors"
            )
        if not session.cookies:
            logger.warning("login POST returned no cookies at all; auth may have failed")

    else:
        raise AuthError(f"unknown auth mode: {auth.mode}")
