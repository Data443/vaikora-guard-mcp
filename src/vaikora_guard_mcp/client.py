"""HTTP client for the Vaikora policy engine.

The MCP server is a thin façade. All real policy logic stays in the
vaikora-llm-gateway, which exposes a stable HTTP API. This client wraps
those endpoints with typed responses and a fail-closed posture.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx

from vaikora_guard_mcp.settings import Settings
from vaikora_guard_mcp.types import (
    Decision,
    DecisionOutcome,
    EnforcementResult,
    PolicyConfig,
)

logger = logging.getLogger(__name__)


class VaikoraGatewayError(RuntimeError):
    """Raised when the gateway returns an error or is unreachable."""


class VaikoraClient:
    """Async HTTP client for the Vaikora gateway."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self._settings = settings
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"vaikora-guard-mcp/{_get_version()}",
        }
        if settings.api_key:
            headers["x-api-key"] = settings.api_key
        if settings.user_jwt:
            headers["Authorization"] = f"Bearer {settings.user_jwt}"

        self._http = httpx.AsyncClient(
            base_url=str(settings.gateway_url).rstrip("/"),
            timeout=settings.timeout_seconds,
            headers=headers,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> VaikoraClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def evaluate(
        self,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> EnforcementResult:
        """Run an action through the full Vaikora enforcement pipeline."""
        payload: dict[str, Any] = {"action": action, "context": context or {}}
        return await self._post_enforcement("/v1/evaluate", payload)

    async def check_module(
        self,
        module: str,
        text: str,
    ) -> EnforcementResult:
        """Run a single content module against text. module must be one of the
        six built-in modules: pii_detection, jailbreak_detection,
        injection_detection, semantic_detection, domain_risk_scoring,
        email_classification."""
        payload = {"module": module, "text": text}
        return await self._post_enforcement("/v1/modules/check", payload)

    async def get_policies(self) -> PolicyConfig:
        """Read the current policy + entitlement configuration."""
        start = time.monotonic()
        path = "/v1/policies"
        try:
            response = await self._http.get(path)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            latency_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "vaikora.http.error",
                extra={"method": "GET", "path": path, "latency_ms": latency_ms, "error": str(exc)},
            )
            raise VaikoraGatewayError(f"Could not fetch policies: {exc}") from exc
        latency_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "vaikora.http.ok",
            extra={
                "method": "GET",
                "path": path,
                "status": response.status_code,
                "latency_ms": latency_ms,
                "response_bytes": len(response.content),
            },
        )
        return PolicyConfig.model_validate(response.json())

    async def write_audit(
        self,
        action: str,
        decision: DecisionOutcome,
        receipt_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append an entry to the gateway audit log."""
        payload = {
            "action": action,
            "decision": decision.value,
            "receipt_id": receipt_id,
            "metadata": metadata or {},
        }
        start = time.monotonic()
        path = "/v1/audit"
        try:
            response = await self._http.post(path, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            latency_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "vaikora.http.error",
                extra={
                    "method": "POST",
                    "path": path,
                    "latency_ms": latency_ms,
                    "error": str(exc),
                    "receipt_id": receipt_id,
                },
            )
            raise VaikoraGatewayError(f"Could not write audit entry: {exc}") from exc
        latency_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "vaikora.http.ok",
            extra={
                "method": "POST",
                "path": path,
                "status": response.status_code,
                "latency_ms": latency_ms,
                "receipt_id": receipt_id,
            },
        )
        return response.json()

    async def _post_enforcement(self, path: str, payload: dict[str, Any]) -> EnforcementResult:
        """POST to an enforcement endpoint and return a typed result."""
        start = time.monotonic()
        try:
            response = await self._http.post(path, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            latency_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "vaikora.http.error",
                extra={
                    "method": "POST",
                    "path": path,
                    "latency_ms": latency_ms,
                    "error": str(exc),
                    "fail_closed": self._settings.fail_closed,
                },
            )
            return self._fallback_result(start, str(exc))

        latency_ms = int((time.monotonic() - start) * 1000)
        data = response.json()
        decision = Decision.model_validate(data["decision"])
        pipeline = [Decision.model_validate(d) for d in data.get("pipeline", [])]
        logger.info(
            "vaikora.http.ok",
            extra={
                "method": "POST",
                "path": path,
                "status": response.status_code,
                "latency_ms": latency_ms,
                "outcome": decision.outcome.value,
                "matched_policy": decision.matched_policy,
                "receipt_id": data.get("receipt_id"),
                "pipeline_steps": len(pipeline),
            },
        )
        return EnforcementResult(
            decision=decision,
            receipt_id=data["receipt_id"],
            pipeline=pipeline,
            latency_ms=latency_ms,
        )

    def _fallback_result(self, start: float, reason: str) -> EnforcementResult:
        """Build a synthetic result when the gateway is unreachable."""
        latency_ms = int((time.monotonic() - start) * 1000)
        outcome = DecisionOutcome.BLOCK if self._settings.fail_closed else DecisionOutcome.ALLOW_LOG
        decision = Decision(
            outcome=outcome,
            reason=(
                f"Vaikora gateway unreachable, fail-closed posture engaged: {reason}"
                if self._settings.fail_closed
                else f"Vaikora gateway unreachable, fail-open posture engaged: {reason}"
            ),
            matched_policy="gateway_unreachable",
            severity="HIGH" if self._settings.fail_closed else "MEDIUM",
        )
        receipt = f"fallback-{uuid.uuid4().hex}"
        logger.error(
            "vaikora.fallback",
            extra={
                "outcome": outcome.value,
                "matched_policy": "gateway_unreachable",
                "latency_ms": latency_ms,
                "receipt_id": receipt,
                "fail_closed": self._settings.fail_closed,
            },
        )
        return EnforcementResult(
            decision=decision,
            receipt_id=receipt,
            pipeline=[],
            latency_ms=latency_ms,
        )


def _get_version() -> str:
    """Read the package version without circular import at module load."""
    try:
        from vaikora_guard_mcp import __version__

        return __version__
    except Exception:
        return "0.0.0"
