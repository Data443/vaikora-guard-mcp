# Vaikora Guard MCP

A Model Context Protocol server that puts deterministic policy enforcement in front of every AI agent tool call.

[![License](https://img.shields.io/badge/License-MIT-64748b?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.x-0a192f?style=flat-square)](https://modelcontextprotocol.io/)
[![Vaikora](https://img.shields.io/badge/Vaikora-policy%20engine-329ED8?style=flat-square)](https://www.vaikora.com/)

---

## What this does

Vaikora Guard MCP lets any MCP client (Claude Desktop, Claude Code, custom agents using the Anthropic SDK) call the Vaikora policy engine before executing a tool action. The agent describes what it wants to do, Vaikora evaluates the request against six deterministic content modules and the active policy set, and returns one of four outcomes with a SHA-256 audit receipt:

| Outcome | Meaning |
|---------|---------|
| `ALLOW` | Action passes every policy, agent can proceed. |
| `ALLOW_LOG` | Action is permitted, but logged for audit review. |
| `CONSTRAIN` | Action is permitted with a modification (e.g. PII redaction). |
| `BLOCK` | Action violates a policy, agent must not proceed. |

The server is a thin façade over the open-source [`vaikora-llm-gateway`](https://github.com/Data443/vaikora-llm-gateway). All policy logic, audit storage, and threat intelligence enrichment live in the gateway. This MCP server adapts the MCP protocol to the gateway's HTTP API.

## Why use it

Most MCP servers expose new capabilities to an agent. Vaikora Guard does the opposite: it adds a deterministic policy gate that an agent (or an orchestrator) consults before acting. Useful when:

- You ship AI agents to customers and need an audit trail per action.
- You want to enforce GRC controls (SOC analyst review, separation of duties, regulated-data handling) on actions an LLM proposes.
- You want a fail-closed posture when the policy engine is unreachable, so unsafe actions cannot slip past.

## Install

```bash
pip install vaikora-guard-mcp
```

Requires Python 3.10 or newer. Installing the package creates a `vaikora-guard-mcp` CLI entry point that runs the MCP server over stdio.

## Configure

Copy `.env.example` to `.env` and fill in:

```bash
VAIKORA_GATEWAY_URL=http://localhost:8000     # or your hosted Vaikora endpoint
VAIKORA_API_KEY=your-vaikora-api-key
VAIKORA_FAIL_CLOSED=true
```

Run a local [`vaikora-llm-gateway`](https://github.com/Data443/vaikora-llm-gateway) instance (Docker Compose recipe lives in that repo) or point at a hosted Vaikora endpoint your team operates.

## Wire it into Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS (or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "vaikora-guard": {
      "command": "vaikora-guard-mcp",
      "env": {
        "VAIKORA_GATEWAY_URL": "http://localhost:8000",
        "VAIKORA_API_KEY": "your-vaikora-api-key"
      }
    }
  }
}
```

Restart Claude Desktop. The `vaikora-guard` server will show up in the MCP indicator and Claude can call its tools.

Full Claude Code config example lives in [`examples/claude-code-config.json`](examples/claude-code-config.json).

## Tools exposed

| Tool | Purpose |
|------|---------|
| `evaluate_action` | Run a candidate action through the full Vaikora enforcement pipeline and return a decision. |
| `check_module` | Run a single content module (PII, jailbreak, injection, semantic, domain risk, email classification) against text. |
| `get_policies` | Return the current policy + entitlement configuration in the gateway. |
| `write_audit` | Append an entry to the Vaikora audit log after an action has executed. |

## Resources exposed

| Resource | Purpose |
|----------|---------|
| `vaikora://policies` | JSON snapshot of the active policy + entitlement set. |
| `vaikora://modules` | List of the six built-in content modules the gateway supports. |

## Example call from an agent

```python
# Pseudocode for an agent using the MCP tools
result = await mcp.call_tool(
    "evaluate_action",
    {
        "action": "DELETE FROM customers WHERE country = 'US'",
        "context": {"target_system": "prod_db", "agent_id": "support-bot-01"},
    },
)
# result is JSON. Example shape:
# {
#   "decision": {"outcome": "BLOCK", "matched_policy": "injection_detection", ...},
#   "receipt_id": "sha256:abc...",
#   "pipeline": [...],
#   "latency_ms": 47
# }
if result["decision"]["outcome"] in ("BLOCK",):
    raise PolicyViolation(result["decision"]["reason"])
```

## Fail-closed by default

If the Vaikora gateway is unreachable, the server returns a synthetic `BLOCK` decision with `matched_policy="gateway_unreachable"`. Set `VAIKORA_FAIL_CLOSED=false` for fail-open behavior. Fail-closed is the recommended posture for production agents handling regulated data.

## Develop

```bash
git clone https://github.com/Data443/vaikora-guard-mcp.git
cd vaikora-guard-mcp
pip install -e ".[dev]"
pytest -q
ruff check .
```

Run the server locally against a real gateway:

```bash
export VAIKORA_GATEWAY_URL=http://localhost:8000
export VAIKORA_API_KEY=...
vaikora-guard-mcp
```

The server will speak MCP over stdio. To talk to it interactively, point an MCP-compatible client at the same command.

## How it relates to Vaikora

Vaikora is Data443's AI runtime control product. It sits between an AI agent and the world, evaluating every proposed action against deterministic policies before execution. Vaikora ships in two shapes:

1. **HTTP gateway**: [`vaikora-llm-gateway`](https://github.com/Data443/vaikora-llm-gateway), an open-source reverse proxy that enforces policy on LLM provider traffic (OpenAI, Anthropic, Gemini, OpenRouter).
2. **MCP server**: this repo, which exposes the same enforcement engine to MCP clients so agent runtimes can call it directly.

Both share the same policy store, decision shape, and audit log. Pick whichever surface fits your agent runtime, or run both side by side.

Learn more about Vaikora: [vaikora.com](https://www.vaikora.com) | [Vaikora docs](https://www.vaikora.com/docs) | [Data443 AI runtime control](https://data443.com/ai-runtime-control-vaikora/).

## License

MIT. See [LICENSE](LICENSE).

## Support

- Issues: [github.com/Data443/vaikora-guard-mcp/issues](https://github.com/Data443/vaikora-guard-mcp/issues)
- Email: support@data443.com
- Vaikora docs: [vaikora.com/docs](https://www.vaikora.com/docs)

Vaikora Guard MCP integrates with the Claude API, Claude Code, and the Anthropic SDK. The integration is built on the open Model Context Protocol and does not imply any endorsement by Anthropic.
