"""GVM connection and API wrapper."""

from __future__ import annotations

import logging
import socket
import ssl
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
        self._socket = socket.create_connection((self.hostname, self.port), timeout=self._timeout)


class VerifiedTLSConnection(TLSConnection):
    """TLS connection that verifies the server certificate by default.

    The upstream TLSConnection silently disables certificate verification when
    no cert files are provided (uses ssl.CERT_NONE + check_hostname=False).
    This subclass overrides _new_socket() to use ssl.create_default_context()
    (system CA bundle) unless an explicit CA file is given or verification is
    explicitly disabled via GVM_TLS_NO_VERIFY=1.
    """

    def __init__(self, *, cafile: str = "", no_verify: bool = False, **kwargs: Any) -> None:
        super().__init__(cafile=cafile or None, **kwargs)
        self._no_verify = no_verify
        self._cafile_override = cafile

    def _new_socket(self) -> ssl.SSLSocket:
        if self._no_verify:
            # Explicit opt-in: fall back to upstream CERT_NONE behaviour.
            return super()._new_socket()

        transport_socket = socket.create_connection(
            (self.hostname, self.port), timeout=self._timeout
        )
        if self._cafile_override:
            # Self-signed GVM cert: verify against the provided CA file.
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=self._cafile_override
            )
        else:
            # Default: verify against the system CA bundle.
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # GVM uses the hostname as CN, not SAN, so hostname check may fail for
        # self-signed certs without a proper SAN; leave check_hostname enabled
        # (default) — operators with self-signed certs should use GVM_TLS_CAFILE.
        sock = context.wrap_socket(transport_socket, server_hostname=self.hostname)
        sock.settimeout(self._timeout)
        return sock


_plain_tcp_warned = False


def _make_connection():
    """Return a GVM connection based on environment configuration.

    - Unix socket if GVM_SOCKET_PATH exists and GVM_HOST is not set.
    - TLS if GVM_TLS=true (or 1/yes) and GVM_HOST is set.
    - Plain TCP socket proxy (socat) otherwise when GVM_HOST is set.
    """
    global _plain_tcp_warned
    if cfg.host:
        if cfg.tls:
            if cfg.tls_no_verify:
                logger.warning(
                    "TLS certificate verification disabled (GVM_TLS_NO_VERIFY=1) — "
                    "connection is susceptible to MITM attacks; "
                    "use GVM_TLS_CAFILE to supply the GVM CA certificate instead"
                )
            return VerifiedTLSConnection(
                hostname=cfg.host,
                port=cfg.port,
                cafile=cfg.tls_cafile,
                no_verify=cfg.tls_no_verify,
            )
        if not _plain_tcp_warned:
            logger.warning(
                "connecting to GVM over plain TCP — credentials will be sent unencrypted; "
                "set GVM_TLS=1 or use a Unix socket for production deployments"
            )
            _plain_tcp_warned = True
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
