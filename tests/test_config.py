"""Tests for CACHE_DB_PATH and AUDIT_LOG_PATH env-var resolution in config.py.

Three cases per variable:
  - absent  : env var not set at all  → must use default
  - empty   : env var set to ""       → must use default (the bug we fixed)
  - explicit: env var set to a path   → must use that path
"""

from __future__ import annotations

import importlib
from pathlib import Path
from unittest.mock import patch

import cve_mcp.config as config_module

DEFAULT_CACHE = str(Path.home() / ".cve-mcp" / "cache.db")
DEFAULT_AUDIT = str(Path.home() / ".cve-mcp" / "audit.log")


def reload_config(monkeypatch, env: dict[str, str | None]) -> object:
    """Reload config with a controlled environment.

    Entries with value None are deleted; all others are set.
    load_dotenv is suppressed so the .env file on disk doesn't interfere.
    """
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)

    with patch("cve_mcp.config.load_dotenv"):
        return importlib.reload(config_module)


# ── CACHE_DB_PATH ────────────────────────────────────────────────────────────


def test_cache_db_path_absent_uses_default(monkeypatch):
    cfg = reload_config(monkeypatch, {"CACHE_DB_PATH": None})
    assert cfg.CACHE_DB_PATH == DEFAULT_CACHE


def test_cache_db_path_empty_uses_default(monkeypatch):
    cfg = reload_config(monkeypatch, {"CACHE_DB_PATH": ""})
    assert cfg.CACHE_DB_PATH == DEFAULT_CACHE


def test_cache_db_path_explicit_uses_value(monkeypatch, tmp_path):
    custom = str(tmp_path / "my.db")
    cfg = reload_config(monkeypatch, {"CACHE_DB_PATH": custom})
    assert cfg.CACHE_DB_PATH == custom


# ── AUDIT_LOG_PATH ───────────────────────────────────────────────────────────


def test_audit_log_path_absent_uses_default(monkeypatch):
    cfg = reload_config(monkeypatch, {"AUDIT_LOG_PATH": None})
    assert cfg.AUDIT_LOG_PATH == DEFAULT_AUDIT


def test_audit_log_path_empty_uses_default(monkeypatch):
    cfg = reload_config(monkeypatch, {"AUDIT_LOG_PATH": ""})
    assert cfg.AUDIT_LOG_PATH == DEFAULT_AUDIT


def test_audit_log_path_explicit_uses_value(monkeypatch, tmp_path):
    custom = str(tmp_path / "audit.log")
    cfg = reload_config(monkeypatch, {"AUDIT_LOG_PATH": custom})
    assert cfg.AUDIT_LOG_PATH == custom
