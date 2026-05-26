"""Vaikora Guard MCP server.

Registers Vaikora policy enforcement as MCP tools + resources so any MCP
client (Claude Desktop, Claude Code, custom agent) can call the policy
engine before executing a tool action.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, TextContent, Tool

from vaikora_guard_mcp.client import VaikoraClient
from vaikora_guard_mcp.logging_config import set_request_id, setup_logging
from vaikora_guard_mcp.settings import Settings, load_settings
from vaikora_guard_mcp.types import EnforcementResult

logger = logging.getLogger(__name__)

MODULE_NAMES = (
    "pii_detection",
    "jailbreak_detection",
    "injection_detection",
    "semantic_detection",
    "domain_risk_scoring",
    "email_classification",
)

# Inputs longer than this are truncated when logged so we never spam the
# log with multi-kilobyte payloads. The full value still goes to the gateway.
_LOGGED_INPUT_LIMIT = 256


def _short(value: Any) -> Any:
    """Return a length-bounded representation of a value for logging."""
    if isinstance(value, str) and len(value) > _LOGGED_INPUT_LIMIT:
        return value[:_LOGGED_INPUT_LIMIT] + f"... <truncated {len(value)} chars>"
    return value


def build_server(settings: Settings | None = None) -> tuple[Server, VaikoraClient]:
    """Construct an MCP server and the Vaikora client that backs it.

    Split out from `run()` so tests can drive the server with a mocked client.
    """
    settings = settings or load_settings()
    client = VaikoraClient(settings)
    server: Server = Server("vaikora-guard")

    # --- Resources ---------------------------------------------------------

    @server.list_resources()
    async def list_resources() -> list[Resource]:
        logger.debug("mcp.list_resources")
        return [
            Resource(
                uri="vaikora://policies",
                name="Active Vaikora policies",
                description=(
                    "Current policy + entitlement configuration in the connected Vaikora gateway."
                ),
                mimeType="application/json",
            ),
            Resource(
                uri="vaikora://modules",
                name="Vaikora content modules",
                description=(
                    "The six built-in content modules that the gateway can evaluate."
                ),
                mimeType="application/json",
            ),
        ]

    @server.read_resource()
    async def read_resource(uri) -> str:
        # The MCP SDK passes a pydantic AnyUrl, not a raw str. Normalize.
        uri_str = str(uri)
        request_id = uuid.uuid4().hex[:12]
        set_request_id(request_id)
        start = time.monotonic()
        logger.info("mcp.read_resource.start", extra={"uri": uri_str})
        try:
            if uri_str == "vaikora://policies":
                config = await client.get_policies()
                body = config.model_dump_json(indent=2)
            elif uri_str == "vaikora://modules":
                body = json.dumps({"modules": list(MODULE_NAMES)}, indent=2)
            else:
                logger.warning("mcp.read_resource.unknown", extra={"uri": uri_str})
                raise ValueError(f"Unknown resource: {uri_str}")
        except Exception:
            logger.exception(
                "mcp.read_resource.error",
                extra={"uri": uri_str, "latency_ms": int((time.monotonic() - start) * 1000)},
            )
            set_request_id(None)
            raise
        logger.info(
            "mcp.read_resource.done",
            extra={
                "uri": uri_str,
                "latency_ms": int((time.monotonic() - start) * 1000),
                "body_bytes": len(body),
            },
        )
        set_request_id(None)
        return body

    # --- Tools -------------------------------------------------------------

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        logger.debug("mcp.list_tools")
        return [
            Tool(
                name="evaluate_action",
                description=(
                    "Run a candidate AI agent action through the full Vaikora "
                    "enforcement pipeline. Returns an ALLOW, ALLOW_LOG, "
                    "CONSTRAIN, or BLOCK decision with a SHA-256 audit receipt."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": (
                                "Free-form description of the action the agent intends to take."
                            ),
                        },
                        "context": {
                            "type": "object",
                            "description": (
                                "Optional structured context (target system, user, parameters)."
                            ),
                            "additionalProperties": True,
                        },
                    },
                    "required": ["action"],
                },
            ),
            Tool(
                name="check_module",
                description=(
                    "Run a single Vaikora content module against a piece of text. "
                    "Use this when you only need to verify one signal (e.g., PII) "
                    "rather than the full pipeline."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "module": {
                            "type": "string",
                            "enum": list(MODULE_NAMES),
                            "description": "Name of the module to invoke.",
                        },
                        "text": {
                            "type": "string",
                            "description": "Text to evaluate.",
                        },
                    },
                    "required": ["module", "text"],
                },
            ),
            Tool(
                name="get_policies",
                description="Return the current Vaikora policy + entitlement configuration.",
                inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            Tool(
                name="write_audit",
                description=(
                    "Append an entry to the Vaikora audit log. Use after an "
                    "agent has executed an action so the receipt records what "
                    "actually happened."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"},
                        "decision": {
                            "type": "string",
                            "enum": ["ALLOW", "ALLOW_LOG", "CONSTRAIN", "BLOCK", "ERROR"],
                        },
                        "receipt_id": {"type": "string"},
                        "metadata": {"type": "object", "additionalProperties": True},
                    },
                    "required": ["action", "decision", "receipt_id"],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        request_id = uuid.uuid4().hex[:12]
        set_request_id(request_id)
        start = time.monotonic()
        logger.info(
            "mcp.call_tool.start",
            extra={
                "tool": name,
                "arg_keys": sorted(arguments.keys()),
                "arg_preview": _short(arguments.get("action") or arguments.get("text") or ""),
            },
        )
        try:
            if name == "evaluate_action":
                result = await client.evaluate(
                    action=arguments["action"],
                    context=arguments.get("context"),
                )
                content = _result_as_content(result)
                _log_call_done(name, start, outcome=result.decision.outcome.value,
                               receipt_id=result.receipt_id,
                               gateway_latency_ms=result.latency_ms)
                set_request_id(None)
                return content

            if name == "check_module":
                result = await client.check_module(
                    module=arguments["module"],
                    text=arguments["text"],
                )
                content = _result_as_content(result)
                _log_call_done(name, start, outcome=result.decision.outcome.value,
                               receipt_id=result.receipt_id,
                               module=arguments["module"],
                               gateway_latency_ms=result.latency_ms)
                set_request_id(None)
                return content

            if name == "get_policies":
                config = await client.get_policies()
                content = [TextContent(type="text", text=config.model_dump_json(indent=2))]
                _log_call_done(name, start, policy_count=len(config.policies),
                               policy_version=config.version)
                set_request_id(None)
                return content

            if name == "write_audit":
                from vaikora_guard_mcp.types import DecisionOutcome

                entry = await client.write_audit(
                    action=arguments["action"],
                    decision=DecisionOutcome(arguments["decision"]),
                    receipt_id=arguments["receipt_id"],
                    metadata=arguments.get("metadata"),
                )
                content = [TextContent(type="text", text=json.dumps(entry, indent=2))]
                _log_call_done(name, start, receipt_id=arguments["receipt_id"])
                set_request_id(None)
                return content

            logger.error("mcp.call_tool.unknown", extra={"tool": name})
            raise ValueError(f"Unknown tool: {name}")
        except Exception:
            logger.exception(
                "mcp.call_tool.error",
                extra={"tool": name, "latency_ms": int((time.monotonic() - start) * 1000)},
            )
            set_request_id(None)
            raise

    return server, client


def _log_call_done(tool: str, start: float, **fields: Any) -> None:
    """Emit a single structured log line for a successful tool call."""
    logger.info(
        "mcp.call_tool.done",
        extra={
            "tool": tool,
            "latency_ms": int((time.monotonic() - start) * 1000),
            **fields,
        },
    )


def _result_as_content(result: EnforcementResult) -> list[TextContent]:
    """Render an EnforcementResult as MCP TextContent. JSON keeps the
    structure machine-readable for downstream agents."""
    return [TextContent(type="text", text=result.model_dump_json(indent=2))]


async def run() -> None:
    """Boot the server over stdio (the standard MCP transport)."""
    settings = load_settings()
    log_path = setup_logging(settings)

    logger.info(
        "mcp.boot",
        extra={
            "gateway_url": str(settings.gateway_url),
            "fail_closed": settings.fail_closed,
            "log_level": settings.log_level,
            "log_file": str(log_path) if log_path else None,
            "log_json": settings.log_json,
        },
    )

    server, client = build_server(settings)
    try:
        async with stdio_server() as (read_stream, write_stream):
            logger.info("mcp.transport.ready", extra={"transport": "stdio"})
            await server.run(read_stream, write_stream, server.create_initialization_options())
    except Exception:
        logger.exception("mcp.run.error")
        raise
    finally:
        await client.aclose()
        logger.info("mcp.shutdown")
