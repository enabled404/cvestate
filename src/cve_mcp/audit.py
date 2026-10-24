from __future__ import annotations

import json
import logging
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

_audit_logger = logging.getLogger("cve_mcp.audit")


def setup_audit_log(log_path: str) -> None:
    if not _audit_logger.hasHandlers():
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=50 * 1024 * 1024,  # 50 MB per file
            backupCount=5,  # 250 MB max total
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        _audit_logger.addHandler(handler)
        _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False


def _sanitize(params: dict) -> dict:
    sanitized = {}
    for k, v in params.items():
        if isinstance(v, str) and ("key" in k.lower() or "token" in k.lower()):
            sanitized[k] = "***REDACTED***"
        else:
            sanitized[k] = v
    return sanitized


def record(
    tool: str,
    params: dict,
    status: str,
    duration_ms: float,
) -> None:
    """Log a structured audit entry.

    status values: "ok" | "not_found" | "error" | "rate_limited" | "invalid_input"
    """
    _audit_logger.info(
        json.dumps(
            {
                "ts": time.time(),
                "tool": tool,
                "params": _sanitize(params),
                "status": status,
                "duration_ms": round(duration_ms, 2),
            }
        )
    )
