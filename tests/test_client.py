"""Tests for the VaikoraClient HTTP façade."""

from __future__ import annotations

import json

import httpx
import pytest

from vaikora_guard_mcp.client import VaikoraClient
from vaikora_guard_mcp.settings import Settings
from vaikora_guard_mcp.types import DecisionOutcome


def _settings(**overrides) -> Settings:
    base = {
        "gateway_url": "https://gateway.test",
        "api_key": "test-key",
        "fail_closed": True,
        "timeout_seconds": 5.0,
        "log_level": "WARNING",
    }
    base.update(overrides)
    return Settings(**base)


def _client(transport: httpx.MockTransport, **overrides) -> VaikoraClient:
    return VaikoraClient(_settings(**overrides), transport=transport)


@pytest.mark.asyncio
async def test_evaluate_returns_typed_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/evaluate"
        assert json.loads(request.content)["action"] == "DROP TABLE users"
        assert request.headers["x-api-key"] == "test-key"
        return httpx.Response(
            200,
            json={
                "decision": {
                    "outcome": "BLOCK",
                    "reason": "destructive_sql_detected",
                    "matched_policy": "injection_detection",
                    "severity": "CRITICAL",
                    "constraint": None,
                },
                "receipt_id": "sha256:abc123",
                "pipeline": [
                    {
                        "outcome": "BLOCK",
                        "reason": "destructive_sql_detected",
                        "matched_policy": "injection_detection",
                        "severity": "CRITICAL",
                        "constraint": None,
                    }
                ],
            },
        )

    async with _client(httpx.MockTransport(handler)) as client:
        result = await client.evaluate("DROP TABLE users", context={"target": "prod"})

    assert result.decision.outcome is DecisionOutcome.BLOCK
    assert result.decision.matched_policy == "injection_detection"
    assert result.receipt_id == "sha256:abc123"
    assert len(result.pipeline) == 1
    assert result.latency_ms >= 0


@pytest.mark.asyncio
async def test_evaluate_fail_closed_when_gateway_errors() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    async with _client(httpx.MockTransport(handler)) as client:
        result = await client.evaluate("send email to all users")

    assert result.decision.outcome is DecisionOutcome.BLOCK
    assert result.decision.matched_policy == "gateway_unreachable"
    assert result.receipt_id.startswith("fallback-")


@pytest.mark.asyncio
async def test_evaluate_fail_open_when_configured() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    async with _client(httpx.MockTransport(handler), fail_closed=False) as client:
        result = await client.evaluate("noop")

    assert result.decision.outcome is DecisionOutcome.ALLOW_LOG
    assert result.decision.matched_policy == "gateway_unreachable"


@pytest.mark.asyncio
async def test_check_module_routes_to_module_endpoint() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "decision": {
                    "outcome": "ALLOW_LOG",
                    "reason": "ssn_detected_redact",
                    "matched_policy": "pii_detection",
                    "severity": "MEDIUM",
                    "constraint": {"redact": ["SSN"]},
                },
                "receipt_id": "sha256:pii001",
                "pipeline": [],
            },
        )

    async with _client(httpx.MockTransport(handler)) as client:
        result = await client.check_module("pii_detection", "SSN 123-45-6789")

    assert captured["path"] == "/v1/modules/check"
    assert captured["body"]["module"] == "pii_detection"
    assert result.decision.constraint == {"redact": ["SSN"]}


@pytest.mark.asyncio
async def test_get_policies_returns_typed_config() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "policies": {"pii_detection": {"enabled": True, "action_on_detect": "BLOCK"}},
                "entitlements": {"providers": {"openai": True}},
                "version": 7,
            },
        )

    async with _client(httpx.MockTransport(handler)) as client:
        config = await client.get_policies()

    assert config.version == 7
    assert config.policies["pii_detection"]["enabled"] is True
    assert config.entitlements["providers"]["openai"] is True


@pytest.mark.asyncio
async def test_write_audit_posts_receipt() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"stored": True, "id": "audit-99"})

    async with _client(httpx.MockTransport(handler)) as client:
        result = await client.write_audit(
            action="rotate api key",
            decision=DecisionOutcome.ALLOW,
            receipt_id="sha256:xyz",
            metadata={"agent": "claude-desktop"},
        )

    assert captured["body"]["decision"] == "ALLOW"
    assert captured["body"]["metadata"] == {"agent": "claude-desktop"}
    assert result["id"] == "audit-99"
