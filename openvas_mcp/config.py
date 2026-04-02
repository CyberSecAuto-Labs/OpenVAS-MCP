"""Centralised configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_VALID_TRANSPORTS = {"stdio", "sse", "streamable-http"}


@dataclass
class Config:
    socket_path: str
    host: str
    port: int
    tls: bool
    tls_cafile: str  # path to CA cert for self-signed GVM certs; empty = use system CA
    tls_no_verify: bool  # skip TLS verification entirely (dangerous; requires explicit opt-in)
    username: str
    password: str = field(repr=False)
    log_level: str
    mcp_transport: str
    mcp_host: str
    mcp_port: int
    mcp_api_keys: str = field(repr=False)
    mcp_policy_file: str
    mcp_allow_unauthenticated: bool
    scan_poll_timeout: int  # max seconds get_scan_status will poll before returning timeout error
    report_max_results: int  # max results returned by fetch_scan_results; 0 = unlimited

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

        raw_poll_timeout = os.environ.get("GVM_SCAN_POLL_TIMEOUT", "3600")
        try:
            scan_poll_timeout = int(raw_poll_timeout)
            if scan_poll_timeout <= 0:
                raise ValueError
        except ValueError:
            raise ValueError(
                f"GVM_SCAN_POLL_TIMEOUT must be a positive integer, got: {raw_poll_timeout!r}"
            ) from None

        raw_max_results = os.environ.get("GVM_REPORT_MAX_RESULTS", "2000")
        try:
            report_max_results = int(raw_max_results)
            if report_max_results < 0:
                raise ValueError
        except ValueError:
            raise ValueError(
                f"GVM_REPORT_MAX_RESULTS must be a non-negative integer, got: {raw_max_results!r}"
            ) from None

        return cls(
            socket_path=os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock"),
            host=os.environ.get("GVM_HOST", ""),
            port=port,
            tls=os.environ.get("GVM_TLS", "").lower() in ("1", "true", "yes"),
            tls_cafile=os.environ.get("GVM_TLS_CAFILE", ""),
            tls_no_verify=os.environ.get("GVM_TLS_NO_VERIFY", "").lower() in ("1", "true", "yes"),
            username=os.environ.get("GVM_USERNAME", "admin"),
            password=os.environ.get("GVM_PASSWORD", ""),
            log_level=log_level,
            mcp_transport=mcp_transport,
            mcp_host=os.environ.get("MCP_HOST", "127.0.0.1"),
            mcp_port=mcp_port,
            mcp_api_keys=os.environ.get("MCP_API_KEYS", ""),
            mcp_policy_file=os.environ.get("MCP_POLICY_FILE", ""),
            mcp_allow_unauthenticated=os.environ.get("MCP_ALLOW_UNAUTHENTICATED", "").lower()
            in ("1", "true", "yes"),
            scan_poll_timeout=scan_poll_timeout,
            report_max_results=report_max_results,
        )

    def missing_required(self) -> list[str]:
        """Return human-readable names of missing required configuration."""
        missing = []
        if not self.host and not os.path.exists(self.socket_path):
            missing.append("GVM_SOCKET_PATH (socket not found) or GVM_HOST")
        if not self.password:
            missing.append("GVM_PASSWORD")
        return missing


try:
    cfg: Config = Config.from_env()
except ValueError as _cfg_err:
    import sys as _sys

    print(f"ERROR: Invalid configuration: {_cfg_err}", file=_sys.stderr)
    _sys.exit(1)
