"""Vaikora Guard MCP server.

Exposes the Vaikora policy engine to Model Context Protocol clients
(Claude Desktop, Claude Code, custom agents) as a set of tools and resources
that evaluate AI agent actions against deterministic policies before they
execute.
"""

from vaikora_guard_mcp.types import (
    Decision,
    DecisionOutcome,
    EnforcementResult,
    PolicyConfig,
)

__version__ = "0.1.1"
__all__ = [
    "Decision",
    "DecisionOutcome",
    "EnforcementResult",
    "PolicyConfig",
    "__version__",
]
