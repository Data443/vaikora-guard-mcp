# Examples

Drop-in configuration snippets for connecting Vaikora Guard MCP to common AI clients.

| File | What it does |
|------|--------------|
| `claude-desktop-config.json` | Wires the server into Claude Desktop on macOS or Windows. |
| `claude-code-config.json` | Wires the server into Claude Code (the CLI / Anthropic SDK agent runtime). |

Both examples assume `vaikora-guard-mcp` is installed and on your `PATH`. If you installed it into a virtualenv, replace the `command` field with the absolute path to the binary (`/path/to/venv/bin/vaikora-guard-mcp`).

## Pointing at a real Vaikora gateway

By default the server expects the gateway at `http://localhost:8000`. Run the open-source [`vaikora-llm-gateway`](https://github.com/Data443/vaikora-llm-gateway) locally for a self-hosted setup, or change `VAIKORA_GATEWAY_URL` to a hosted Vaikora endpoint your team manages.

## Trying it without a gateway

If you just want to see the MCP server boot and register tools without a real gateway, set `VAIKORA_FAIL_CLOSED=false` and start the server. Tool calls will return synthetic `ALLOW_LOG` results with a `gateway_unreachable` matched policy until a gateway is configured.
