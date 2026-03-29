"""Centralised configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@dataclass
class Config:
    socket_path: str
    host: str
    port: int
    tls: bool
    username: str
    password: str
    log_level: str

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

        return cls(
            socket_path=os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock"),
            host=os.environ.get("GVM_HOST", ""),
            port=port,
            tls=os.environ.get("GVM_TLS", "").lower() in ("1", "true", "yes"),
            username=os.environ.get("GVM_USERNAME", "admin"),
            password=os.environ.get("GVM_PASSWORD", ""),
            log_level=log_level,
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
