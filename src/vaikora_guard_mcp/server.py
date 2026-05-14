"""Vaikora Guard MCP server.

Registers Vaikora policy enforcement as MCP tools + resources so any MCP
client (Claude Desktop, Claude Code, custom agent) can call the policy
engine before executing a tool action.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, TextContent, Tool

from vaikora_guard_mcp.client import VaikoraClient
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


def build_server(settings: Settings | None = None) -> tuple[Server, VaikoraClient]:
    """Construct an MCP server and the Vaikora client that backs it.

    Split out from `main()` so tests can drive the server with a
    mocked client.
    """
    settings = settings or load_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
    client = VaikoraClient(settings)
    server: Server = Server("vaikora-guard")

    # --- Resources ---------------------------------------------------------

    @server.list_resources()
    async def list_resources() -> list[Resource]:
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
                description="The six built-in content modules that the gateway can evaluate.",
                mimeType="application/json",
            ),
        ]

    @server.read_resource()
    async def read_resource(uri: str) -> str:
        if uri == "vaikora://policies":
            config = await client.get_policies()
            return config.model_dump_json(indent=2)
        if uri == "vaikora://modules":
            return json.dumps({"modules": list(MODULE_NAMES)}, indent=2)
        raise ValueError(f"Unknown resource: {uri}")

    # --- Tools -------------------------------------------------------------

    @server.list_tools()
    async def list_tools() -> list[Tool]:
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
                            "enum": ["ALLOW", "ALLOW_LOG", "CONSTRAIN", "BLOCK"],
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
        if name == "evaluate_action":
            result = await client.evaluate(
                action=arguments["action"],
                context=arguments.get("context"),
            )
            return _result_as_content(result)

        if name == "check_module":
            result = await client.check_module(
                module=arguments["module"],
                text=arguments["text"],
            )
            return _result_as_content(result)

        if name == "get_policies":
            config = await client.get_policies()
            return [TextContent(type="text", text=config.model_dump_json(indent=2))]

        if name == "write_audit":
            from vaikora_guard_mcp.types import DecisionOutcome

            entry = await client.write_audit(
                action=arguments["action"],
                decision=DecisionOutcome(arguments["decision"]),
                receipt_id=arguments["receipt_id"],
                metadata=arguments.get("metadata"),
            )
            return [TextContent(type="text", text=json.dumps(entry, indent=2))]

        raise ValueError(f"Unknown tool: {name}")

    return server, client


def _result_as_content(result: EnforcementResult) -> list[TextContent]:
    """Render an EnforcementResult as MCP TextContent. JSON keeps the
    structure machine-readable for downstream agents."""
    return [TextContent(type="text", text=result.model_dump_json(indent=2))]


async def run() -> None:
    """Boot the server over stdio (the standard MCP transport)."""
    server, client = build_server()
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    finally:
        await client.aclose()
