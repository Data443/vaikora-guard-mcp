"""Logging configuration for the Vaikora Guard MCP server.

Two design constraints shape this module:

1. MCP servers communicate JSON-RPC over stdout. Anything written to stdout
   that is not a valid protocol message will break the client. All logs MUST
   go to stderr (or a file). `setup_logging` enforces that.

2. Operators need post-hoc visibility. The server runs as a subprocess of
   Claude Desktop / Claude Code, so an in-memory log is not enough. By
   default we also write to a rotating file in the OS cache directory so
   operators can tail it.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vaikora_guard_mcp.settings import Settings

# Per-call correlation id, set at the start of every tool dispatch and
# included on every log record while that call is in flight.
_request_id: ContextVar[str | None] = ContextVar("vaikora_request_id", default=None)


# Field names whose values must be redacted whenever they appear in log
# records or extra dicts. Tokens, API keys, JWTs, and Authorization headers
# all qualify.
_REDACTED_FIELDS = frozenset(
    {
        "api_key",
        "vaikora_api_key",
        "user_jwt",
        "vaikora_user_jwt",
        "authorization",
        "x-api-key",
        "password",
        "secret",
        "token",
    }
)

# Patterns that match secret-like values embedded in URLs or message strings.
_URL_CRED_RE = re.compile(r"(https?://)[^:/@\s]+:[^@\s]+@", re.IGNORECASE)
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-+/=_]{16,}", re.IGNORECASE)
# GitHub-style classic + fine-grained tokens (ghp_, gho_, ghu_, ghs_, ghr_).
_GH_TOKEN_RE = re.compile(r"\bgh[opusr]_[A-Za-z0-9_]{20,}", re.IGNORECASE)


def set_request_id(value: str | None) -> None:
    """Bind a correlation id to the current async/sync context."""
    _request_id.set(value)


def get_request_id() -> str | None:
    return _request_id.get()


def _sanitize_value(value: Any) -> Any:
    """Recursively redact secret-like fields and patterns from a value."""
    if isinstance(value, str):
        scrubbed = _URL_CRED_RE.sub(r"\1<redacted>@", value)
        scrubbed = _BEARER_RE.sub(r"\1<redacted>", scrubbed)
        scrubbed = _GH_TOKEN_RE.sub("<redacted>", scrubbed)
        return scrubbed
    if isinstance(value, dict):
        return {
            k: ("<redacted>" if k.lower() in _REDACTED_FIELDS else _sanitize_value(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(_sanitize_value(v) for v in value)
    return value


class _JsonFormatter(logging.Formatter):
    """Format every log record as a single JSON object, one per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "msg": _sanitize_value(record.getMessage()),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        # Capture custom `extra=` fields without trampling stdlib record attrs.
        reserved = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
            "message",
            "asctime",
        }
        for key, value in record.__dict__.items():
            if key in reserved:
                continue
            if key.lower() in _REDACTED_FIELDS:
                payload[key] = "<redacted>"
            else:
                payload[key] = _sanitize_value(value)

        request_id = get_request_id()
        if request_id and "request_id" not in payload:
            payload["request_id"] = request_id

        return json.dumps(payload, default=str, separators=(",", ":"))


class _HumanFormatter(logging.Formatter):
    """Compact human-readable formatter used when VAIKORA_LOG_JSON=false."""

    default_msec_format = "%s.%03d"

    def format(self, record: logging.LogRecord) -> str:
        request_id = get_request_id()
        prefix = f"[{request_id}] " if request_id else ""
        base = super().format(record)
        return f"{prefix}{base}"


def _default_log_path() -> Path:
    """Pick a sensible default log file location per platform."""
    if sys.platform == "darwin":
        root = Path.home() / "Library" / "Logs" / "vaikora-guard-mcp"
    elif os.name == "nt":  # Windows
        appdata = os.environ.get("LOCALAPPDATA")
        root = (
            Path(appdata) / "vaikora-guard-mcp" / "logs"
            if appdata
            else Path.home() / ".vaikora-guard-mcp" / "logs"
        )
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        root = (
            Path(xdg_cache) / "vaikora-guard-mcp"
            if xdg_cache
            else Path.home() / ".cache" / "vaikora-guard-mcp"
        )
    return root / "vaikora-guard-mcp.log"


def setup_logging(settings: Settings) -> Path | None:
    """Configure the root logger for the MCP server.

    Returns the path of the rotating file (if file logging is enabled) so
    callers can echo it to operators on startup.
    """
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    # Wipe any handlers a prior boot or import may have left behind.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter: logging.Formatter
    if settings.log_json:
        formatter = _JsonFormatter()
    else:
        formatter = _HumanFormatter(
            fmt="%(asctime)s %(levelname)-7s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    # stderr handler is mandatory: stdout carries the MCP JSON-RPC stream.
    stderr_handler = logging.StreamHandler(stream=sys.stderr)
    stderr_handler.setFormatter(formatter)
    root.addHandler(stderr_handler)

    log_file_path: Path | None = None
    if settings.log_to_file:
        log_file_path = Path(settings.log_file) if settings.log_file else _default_log_path()
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=settings.log_file_max_bytes,
            backupCount=settings.log_file_backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    # Tame noisy third-party loggers unless DEBUG was explicitly requested.
    if level > logging.DEBUG:
        for noisy in ("httpx", "httpcore", "asyncio"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    return log_file_path


__all__ = [
    "get_request_id",
    "set_request_id",
    "setup_logging",
]
