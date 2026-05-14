"""Typed models for Vaikora Guard MCP responses.

These match the decision shape returned by the vaikora-llm-gateway HTTP API
so the MCP server can be a thin façade rather than re-implementing policy
logic locally.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DecisionOutcome(str, Enum):
    """Possible outcomes of a policy evaluation."""

    ALLOW = "ALLOW"
    ALLOW_LOG = "ALLOW_LOG"
    CONSTRAIN = "CONSTRAIN"
    BLOCK = "BLOCK"


class Decision(BaseModel):
    """A single policy decision for a candidate AI action."""

    outcome: DecisionOutcome
    reason: str = Field(
        description="Human-readable explanation for the decision. Always populated."
    )
    matched_policy: str | None = Field(
        default=None,
        description="Name of the policy that produced this outcome, if any.",
    )
    severity: str | None = Field(
        default=None,
        description="LOW, MEDIUM, HIGH, or CRITICAL when the policy assigns severity.",
    )
    constraint: dict[str, Any] | None = Field(
        default=None,
        description="Set when outcome is CONSTRAIN: the modification to apply.",
    )


class EnforcementResult(BaseModel):
    """Full enforcement result returned to the MCP client."""

    decision: Decision
    receipt_id: str = Field(
        description="SHA-256 audit receipt identifier for this evaluation."
    )
    pipeline: list[Decision] = Field(
        default_factory=list,
        description="Per-module decisions that composed the final outcome.",
    )
    latency_ms: int = Field(
        description="End-to-end latency observed by the MCP server."
    )


class PolicyConfig(BaseModel):
    """Current policy configuration as reported by the gateway."""

    policies: dict[str, dict[str, Any]]
    entitlements: dict[str, Any]
    version: int = Field(description="Monotonic version number of the active config.")
