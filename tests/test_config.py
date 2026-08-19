import json
import os

import pytest

from vulnscanner.config import ScanConfig


def test_defaults():
    cfg = ScanConfig()
    assert cfg.depth == 1
    assert cfg.threads == 8
    assert cfg.auth.mode == "none"


def test_from_dict_overrides_defaults():
    cfg = ScanConfig.from_dict({"target": "https://example.com", "depth": 3})
    assert cfg.target == "https://example.com"
    assert cfg.depth == 3
    assert cfg.threads == 8  # untouched default


def test_from_json_file(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"target": "https://example.com", "rate_limit": 2}))
    cfg = ScanConfig.from_file(str(path))
    assert cfg.target == "https://example.com"
    assert cfg.rate_limit == 2


def test_env_override(monkeypatch):
    monkeypatch.setenv("VULNSCAN_THREADS", "16")
    monkeypatch.setenv("VULNSCAN_VERIFY_SSL", "false")
    cfg = ScanConfig().apply_env_overrides()
    assert cfg.threads == 16
    assert cfg.verify_ssl is False


def test_validate_requires_target():
    cfg = ScanConfig()
    with pytest.raises(ValueError):
        cfg.validate()


def test_validate_rejects_bad_auth_mode():
    cfg = ScanConfig(target="https://example.com")
    cfg.auth.mode = "smoke-signal"
    with pytest.raises(ValueError):
        cfg.validate()


def test_as_dict_redacts_secrets():
    cfg = ScanConfig(target="https://example.com")
    cfg.auth.mode = "bearer"
    cfg.auth.token = "super-secret"
    d = cfg.as_dict()
    assert d["auth"]["token"] == "***REDACTED***"
