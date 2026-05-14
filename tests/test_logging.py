"""Tests for the structured logging layer."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from vaikora_guard_mcp.logging_config import (
    _JsonFormatter,
    get_request_id,
    set_request_id,
    setup_logging,
)
from vaikora_guard_mcp.settings import Settings


def _make_settings(**overrides) -> Settings:
    base = {
        "gateway_url": "https://gateway.test",
        "api_key": "test-key",
        "fail_closed": True,
        "timeout_seconds": 5.0,
        "log_level": "INFO",
        "log_json": True,
        "log_to_file": False,
    }
    base.update(overrides)
    return Settings(**base)


def test_setup_logging_writes_to_stderr_not_stdout(tmp_path: Path, capsys) -> None:
    setup_logging(_make_settings(log_to_file=False))
    logging.getLogger("vaikora_guard_mcp.test").info("hello-stderr")
    captured = capsys.readouterr()
    assert captured.out == ""  # stdout MUST stay clean for MCP JSON-RPC
    assert "hello-stderr" in captured.err


def test_setup_logging_writes_rotating_file(tmp_path: Path) -> None:
    log_path = tmp_path / "vaikora.log"
    setup_logging(
        _make_settings(log_to_file=True, log_file=str(log_path)),
    )
    logging.getLogger("vaikora_guard_mcp.test").info("hello-file")
    content = log_path.read_text(encoding="utf-8")
    assert "hello-file" in content


def test_json_formatter_emits_one_object_per_line() -> None:
    formatter = _JsonFormatter()
    record = logging.LogRecord(
        name="vaikora_guard_mcp.client",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="vaikora.http.ok",
        args=(),
        exc_info=None,
    )
    record.status = 200
    record.latency_ms = 42
    record.path = "/v1/evaluate"

    output = formatter.format(record)
    payload = json.loads(output)
    assert payload["msg"] == "vaikora.http.ok"
    assert payload["status"] == 200
    assert payload["latency_ms"] == 42
    assert payload["path"] == "/v1/evaluate"
    assert payload["level"] == "INFO"


def test_json_formatter_redacts_sensitive_fields() -> None:
    formatter = _JsonFormatter()
    record = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hi",
        args=(),
        exc_info=None,
    )
    record.api_key = "ghp_supersecret"
    record.user_jwt = "eyJhbGciOiJIUzI1NiJ9.payload.sig"
    record.payload = {"authorization": "Bearer xyz123", "ok": True}

    payload = json.loads(formatter.format(record))
    assert payload["api_key"] == "<redacted>"
    assert payload["user_jwt"] == "<redacted>"
    assert payload["payload"]["authorization"] == "<redacted>"
    assert payload["payload"]["ok"] is True


def test_json_formatter_scrubs_bearer_tokens_in_message_text() -> None:
    formatter = _JsonFormatter()
    record = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="header was Bearer ghp_thisistoolongtoleakinto_a_log_file_x",
        args=(),
        exc_info=None,
    )
    record.url = "https://user:secret@gateway.test/v1/evaluate"

    payload = json.loads(formatter.format(record))
    assert "ghp_thisistoolong" not in payload["msg"]
    assert "<redacted>" in payload["msg"]
    assert "user:secret" not in payload["url"]
    assert "<redacted>@" in payload["url"]


def test_request_id_is_attached_to_log_records() -> None:
    formatter = _JsonFormatter()
    set_request_id("req-abc-123")
    try:
        record = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="tagged",
            args=(),
            exc_info=None,
        )
        payload = json.loads(formatter.format(record))
        assert payload["request_id"] == "req-abc-123"
        assert get_request_id() == "req-abc-123"
    finally:
        set_request_id(None)


def test_human_formatter_includes_request_id_prefix(capsys) -> None:
    setup_logging(_make_settings(log_json=False, log_to_file=False))
    set_request_id("req-xyz")
    try:
        logging.getLogger("vaikora_guard_mcp.test").info("alarm")
        err = capsys.readouterr().err
        assert "[req-xyz]" in err
        assert "alarm" in err
    finally:
        set_request_id(None)


def test_third_party_loggers_quieted_above_debug(capsys) -> None:
    setup_logging(_make_settings(log_level="INFO", log_to_file=False))
    logging.getLogger("httpx").info("noisy")
    logging.getLogger("httpcore").info("noisy")
    err = capsys.readouterr().err
    # httpx/httpcore info-level should be suppressed
    assert "noisy" not in err


@pytest.fixture(autouse=True)
def _reset_logging():
    """Reset the root logger after every test so handler state doesn't bleed."""
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    set_request_id(None)
