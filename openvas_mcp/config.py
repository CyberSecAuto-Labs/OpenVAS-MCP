"""Centralised configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_VALID_TRANSPORTS = {"stdio", "sse", "streamable-http"}


@dataclass
class Config:
    socket_path: str
    host: str
    port: int
    tls: bool
    username: str
    password: str
    log_level: str
    mcp_transport: str
    mcp_host: str
    mcp_port: int

    @classmethod
    def from_env(cls) -> Config:
        raw_port = os.environ.get("GVM_PORT", "9390")
        try:
            port = int(raw_port)
        except ValueError:
            raise ValueError(f"GVM_PORT must be an integer, got: {raw_port!r}") from None

        log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
        if log_level not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"LOG_LEVEL must be one of {sorted(_VALID_LOG_LEVELS)}, got: {log_level!r}"
            )

        mcp_transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
        if mcp_transport not in _VALID_TRANSPORTS:
            raise ValueError(
                f"MCP_TRANSPORT must be one of {sorted(_VALID_TRANSPORTS)}, got: {mcp_transport!r}"
            )

        raw_mcp_port = os.environ.get("MCP_PORT", "8000")
        try:
            mcp_port = int(raw_mcp_port)
        except ValueError:
            raise ValueError(f"MCP_PORT must be an integer, got: {raw_mcp_port!r}") from None

        return cls(
            socket_path=os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock"),
            host=os.environ.get("GVM_HOST", ""),
            port=port,
            tls=os.environ.get("GVM_TLS", "").lower() in ("1", "true", "yes"),
            username=os.environ.get("GVM_USERNAME", "admin"),
            password=os.environ.get("GVM_PASSWORD", ""),
            log_level=log_level,
            mcp_transport=mcp_transport,
            mcp_host=os.environ.get("MCP_HOST", "127.0.0.1"),
            mcp_port=mcp_port,
        )

    def missing_required(self) -> list[str]:
        """Return human-readable names of missing required configuration."""
        missing = []
        if not self.host and not os.path.exists(self.socket_path):
            missing.append("GVM_SOCKET_PATH (socket not found) or GVM_HOST")
        if not self.password:
            missing.append("GVM_PASSWORD")
        return missing


cfg: Config = Config.from_env()
