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
        description="Logging level for the MCP server (DEBUG, INFO, WARNING, ERROR).",
    )
    log_json: bool = Field(
        default=True,
        description=(
            "When true, emit one JSON object per log line. "
            "Set to false for human-readable output during local development."
        ),
    )
    log_to_file: bool = Field(
        default=True,
        description=(
            "When true, also write logs to a rotating file. "
            "Path is controlled by log_file or defaults to the OS cache directory."
        ),
    )
    log_file: str = Field(
        default="",
        description=(
            "Explicit path for the rotating log file. "
            "Leave blank to use the per-platform default."
        ),
    )
    log_file_max_bytes: int = Field(
        default=10 * 1024 * 1024,
        ge=64 * 1024,
        description="Rotate the log file once it grows beyond this size (bytes).",
    )
    log_file_backup_count: int = Field(
        default=5,
        ge=0,
        le=20,
        description="How many rotated log files to keep.",
    )


def load_settings() -> Settings:
    """Load settings from the environment (and .env file if present)."""
    return Settings()
