"""Tests for the MCP server wiring."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from mcp.types import ReadResourceRequest, ReadResourceRequestParams
from pydantic import AnyUrl

from vaikora_guard_mcp.client import VaikoraClient
from vaikora_guard_mcp.server import MODULE_NAMES, build_server
from vaikora_guard_mcp.settings import Settings


def _settings() -> Settings:
    return Settings(
        gateway_url="https://gateway.test",
        api_key="test-key",
        fail_closed=True,
        timeout_seconds=5.0,
        log_level="WARNING",
    )


def test_module_names_match_six_modules() -> None:
    assert MODULE_NAMES == (
        "pii_detection",
        "jailbreak_detection",
        "injection_detection",
        "semantic_detection",
        "domain_risk_scoring",
        "email_classification",
    )


@pytest.mark.asyncio
async def test_build_server_registers_expected_handlers() -> None:
    """The MCP Server should have all five request handlers wired up after build."""
    server, client = build_server(_settings())
    try:
        handler_names = {h.__name__ for h in server.request_handlers}
        # mcp library registers PingRequest automatically; the rest come from our decorators.
        for expected in (
            "PingRequest",
            "ListResourcesRequest",
            "ReadResourceRequest",
            "ListToolsRequest",
            "CallToolRequest",
        ):
            assert expected in handler_names, f"missing handler {expected}"
        assert server.name == "vaikora-guard"
    finally:
        await client.aclose()


class _StubTransport(httpx.MockTransport):
    """Convenience wrapper that records every request path + body."""

    def __init__(self, response_map: dict[str, dict[str, Any]]) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._response_map = response_map

        def handler(request: httpx.Request) -> httpx.Response:
            body: dict[str, Any] = {}
            if request.content:
                body = json.loads(request.content)
            self.calls.append((request.url.path, body))
            payload = self._response_map.get(request.url.path)
            if payload is None:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json=payload)

        super().__init__(handler)


@pytest.mark.asyncio
async def test_evaluate_round_trip_through_client() -> None:
    """End-to-end: the client used by the server hits /v1/evaluate correctly."""
    transport = _StubTransport(
        {
            "/v1/evaluate": {
                "decision": {
                    "outcome": "ALLOW",
                    "reason": "no_policy_matched",
                    "matched_policy": None,
                    "severity": None,
                    "constraint": None,
                },
                "receipt_id": "sha256:ok",
                "pipeline": [],
            },
        }
    )

    client = VaikoraClient(_settings(), transport=transport)
    try:
        result = await client.evaluate("read a public README file")
    finally:
        await client.aclose()

    assert result.decision.outcome.value == "ALLOW"
    assert result.receipt_id == "sha256:ok"
    assert transport.calls[0][0] == "/v1/evaluate"
    assert transport.calls[0][1]["action"] == "read a public README file"


@pytest.mark.asyncio
async def test_read_resource_handler_accepts_anyurl() -> None:
    """Regression: the MCP SDK passes pydantic.AnyUrl, not str, to read_resource.

    Pre-0.1.1 server compared `uri == 'vaikora://modules'` (str equality) and
    raised "Unknown resource" for every request even though the SDK had already
    routed through list_resources to expose them.
    """
    server, client = build_server(_settings())
    try:
        handler = server.request_handlers[ReadResourceRequest]
        req = ReadResourceRequest(
            method="resources/read",
            params=ReadResourceRequestParams(uri=AnyUrl("vaikora://modules")),
        )
        result = await handler(req)
        # Result wraps a ServerResult with .root.contents
        contents = result.root.contents
        assert len(contents) == 1
        text = contents[0].text
        body = json.loads(text)
        assert set(body["modules"]) == set(MODULE_NAMES)
    finally:
        await client.aclose()
