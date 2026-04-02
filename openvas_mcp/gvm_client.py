"""GVM connection and API wrapper."""

from __future__ import annotations

import logging
import socket
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.connections._unix import AbstractGvmConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

from .config import cfg

logger = logging.getLogger(__name__)


class SocketConnection(AbstractGvmConnection):
    """Plain (non-TLS) TCP connection to a GVM socket proxy (e.g. socat)."""

    def __init__(
        self,
        hostname: str = "127.0.0.1",
        port: int = 9390,
        timeout: int | float | None = 60,
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
    if cfg.host:
        if cfg.tls:
            return TLSConnection(hostname=cfg.host, port=cfg.port)
        logger.warning(
            "connecting to GVM over plain TCP — credentials will be sent unencrypted; "
            "set GVM_TLS=1 or use a Unix socket for production deployments"
        )
        return SocketConnection(hostname=cfg.host, port=cfg.port)
    return UnixSocketConnection(path=cfg.socket_path)


@contextmanager
def gmp_session() -> Generator[Any, None, None]:
    """Yield an authenticated GMP session, closing it on exit."""
    connection = _make_connection()
    transform = EtreeCheckCommandTransform()
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(cfg.username, cfg.password)
        yield gmp
