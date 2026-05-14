"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration for the Vaikora Guard MCP server."""

    model_config = SettingsConfigDict(
        env_prefix="VAIKORA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    gateway_url: HttpUrl = Field(
        default=HttpUrl("http://localhost:8000"),
        description="URL of the vaikora-llm-gateway HTTP API.",
    )
    api_key: str = Field(
        default="",
        description="API key for the Vaikora gateway. Sent as x-api-key header.",
    )
    user_jwt: str = Field(
        default="",
        description="Optional JWT for end-user attribution. Sent as bearer token.",
    )
    timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        le=120.0,
        description="HTTP timeout for outbound calls to the gateway.",
    )
    fail_closed: bool = Field(
        default=True,
        description=(
            "If true, block when the gateway is unreachable. If false, allow with a warning."
        ),
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level for the MCP server.",
    )


def load_settings() -> Settings:
    """Load settings from the environment (and .env file if present)."""
    return Settings()
