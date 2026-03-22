"""GVM connection and API wrapper."""

from __future__ import annotations

import os
import socket
from contextlib import contextmanager
from typing import Generator, Union

from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.connections._unix import AbstractGvmConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform


DEFAULT_SOCKET_PATH = os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
GVM_HOST = os.environ.get("GVM_HOST", "")
GVM_PORT = int(os.environ.get("GVM_PORT", "9393"))
GVM_TLS = os.environ.get("GVM_TLS", "").lower() in ("1", "true", "yes")
GVM_USERNAME = os.environ.get("GVM_USERNAME", "admin")
GVM_PASSWORD = os.environ.get("GVM_PASSWORD", "")


class SocketConnection(AbstractGvmConnection):
    """Plain (non-TLS) TCP connection to a GVM socket proxy (e.g. socat)."""

    def __init__(
        self,
        hostname: str = "127.0.0.1",
        port: int = 9393,
        timeout: Union[int, float, None] = 60,
    ) -> None:
        super().__init__(timeout=timeout)
        self.hostname = hostname
        self.port = port

    def connect(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self._timeout)
        self._socket.connect((self.hostname, self.port))


def _make_connection():
    """Return a GVM connection based on environment configuration.

    - Unix socket if GVM_SOCKET_PATH exists and GVM_HOST is not set.
    - TLS if GVM_TLS=true (or 1/yes) and GVM_HOST is set.
    - Plain TCP socket proxy (socat) otherwise when GVM_HOST is set.
    """
    if GVM_HOST:
        if GVM_TLS:
            return TLSConnection(hostname=GVM_HOST, port=GVM_PORT)
        return SocketConnection(hostname=GVM_HOST, port=GVM_PORT)
    return UnixSocketConnection(path=DEFAULT_SOCKET_PATH)


@contextmanager
def gmp_session() -> Generator[Gmp, None, None]:
    """Yield an authenticated GMP session, closing it on exit."""
    connection = _make_connection()
    transform = EtreeCheckCommandTransform()
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        yield gmp


def require_env() -> list[str]:
    """Return a list of missing required environment variables."""
    missing = []
    if not GVM_HOST and not os.path.exists(DEFAULT_SOCKET_PATH):
        missing.append("GVM_SOCKET_PATH (socket not found) or GVM_HOST")
    if not GVM_PASSWORD:
        missing.append("GVM_PASSWORD")
    return missing
