"""
Configuration layer.

Precedence (highest wins): CLI flags  >  environment variables (VULNSCAN_*)  >
config file (--config path.yaml/json)  >  built-in defaults.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields, asdict
from typing import Optional


def _env_prefix() -> str:
    return "VULNSCAN_"


@dataclass
class AuthConfig:
    mode: str = "none"                 # none | basic | bearer | header | cookie
    username: str = ""
    password: str = ""
    token: str = ""
    header_name: str = ""
    header_value: str = ""
    login_url: str = ""
    login_data: dict = field(default_factory=dict)
    cookie_name: str = ""


@dataclass
class ScanConfig:
    target: str = ""
    depth: int = 1
    timeout: float = 10.0
    delay: float = 0.0                  # fixed extra delay per request (seconds)
    rate_limit: float = 5.0             # max requests per second, 0 = unlimited
    threads: int = 8
    verify_ssl: bool = True
    proxy: Optional[str] = None
    user_agent: str = "Mozilla/5.0 (compatible; VulnScanner/2.0; +https://github.com/)"
    follow_redirects: bool = True
    max_redirects: int = 5
    max_retries: int = 3
    backoff_factor: float = 0.5
    retry_status_codes: tuple = (429, 500, 502, 503, 504)
    extra_headers: dict = field(default_factory=dict)
    auth: AuthConfig = field(default_factory=AuthConfig)
    output_html: str = "scan_report.html"
    output_json: Optional[str] = None
    log_level: str = "INFO"
    log_file: Optional[str] = None
    include_active_checks: bool = True  # XSS/SQLi/open-redirect probing (intrusive)
    exclude_checks: tuple = ()
    max_pages: int = 50

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        with open(path, "r", encoding="utf-8") as fh:
            if path.endswith((".yaml", ".yml")):
                try:
                    import yaml
                except ImportError as e:
                    raise RuntimeError(
                        "PyYAML is required for YAML config files: pip install pyyaml"
                    ) from e
                data = yaml.safe_load(fh) or {}
            else:
                data = json.load(fh)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        data = dict(data)
        auth_data = data.pop("auth", None)
        known = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known}
        cfg = cls(**filtered)
        if auth_data:
            cfg.auth = AuthConfig(**{k: v for k, v in auth_data.items()
                                      if k in {f.name for f in fields(AuthConfig)}})
        return cfg

    def apply_env_overrides(self) -> "ScanConfig":
        prefix = _env_prefix()
        for f in fields(self):
            env_key = prefix + f.name.upper()
            if env_key in os.environ:
                raw = os.environ[env_key]
                current = getattr(self, f.name)
                setattr(self, f.name, self._coerce(raw, current))
        return self

    @staticmethod
    def _coerce(raw: str, current):
        if isinstance(current, bool):
            return raw.lower() in ("1", "true", "yes", "on")
        if isinstance(current, int):
            return int(raw)
        if isinstance(current, float):
            return float(raw)
        return raw

    def validate(self) -> None:
        if not self.target:
            raise ValueError("target URL is required")
        if self.depth < 1:
            raise ValueError("depth must be >= 1")
        if self.threads < 1:
            raise ValueError("threads must be >= 1")
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        if self.rate_limit < 0:
            raise ValueError("rate_limit must be >= 0")
        if self.auth.mode not in ("none", "basic", "bearer", "header", "cookie"):
            raise ValueError(f"unknown auth mode: {self.auth.mode}")

    def as_dict(self) -> dict:
        d = asdict(self)
        # never leak secrets into reports/logs
        if d.get("auth", {}).get("password"):
            d["auth"]["password"] = "***REDACTED***"
        if d.get("auth", {}).get("token"):
            d["auth"]["token"] = "***REDACTED***"
        return d
