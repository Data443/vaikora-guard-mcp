"""Command-line entry point for `vaikora-guard-mcp`."""

from __future__ import annotations

import asyncio

from vaikora_guard_mcp.server import run


def main() -> None:
    """Run the Vaikora Guard MCP server over stdio."""
    asyncio.run(run())


if __name__ == "__main__":
    main()
