"""API-key authentication for HTTP transports."""

from __future__ import annotations

import contextvars
import hmac
import logging
import re
from dataclasses import dataclass

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

_client_ctx: contextvars.ContextVar[ClientIdentity | None] = contextvars.ContextVar(
    "client_identity", default=None
)


@dataclass(frozen=True)
class ClientIdentity:
    """Authenticated client identity extracted from an API key."""

    client_id: str


def get_current_client() -> ClientIdentity | None:
    """Return the identity of the authenticated client for the current request.

    Returns None when running under stdio transport (trusted local process).
    """
    return _client_ctx.get()


def _parse_api_keys(raw: str) -> dict[str, str]:
    """Parse MCP_API_KEYS value into {token: client_id} mapping.

    Format: "token1:name1,token2:name2"
    If no name is given for a token, the token itself is used as the client_id.
    """
    store: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        token, _, name = entry.partition(":")
        token = token.strip()
        name = name.strip() or token
        if token:
            store[token] = name
    return store


class APIKeyStore:
    """Holds API key → client_id mappings loaded from MCP_API_KEYS."""

    def __init__(self, keys_raw: str = "") -> None:
        self._store: dict[str, str] = _parse_api_keys(keys_raw)

    def validate(self, token: str) -> ClientIdentity | None:
        """Return the ClientIdentity for a valid token, or None if not found.

        Uses constant-time comparison to prevent timing side-channels.
        """
        token_bytes = token.encode()
        matched: str | None = None
        for stored_token, client_id in self._store.items():
            if hmac.compare_digest(stored_token.encode(), token_bytes):
                matched = client_id
        return ClientIdentity(client_id=matched) if matched is not None else None

    @property
    def is_empty(self) -> bool:
        return not self._store


_BEARER_RE = re.compile(r"^Bearer\s+(.+)$", re.IGNORECASE)
_SKIP_PATHS = frozenset({"/health"})


class AuthMiddleware:
    """Pure ASGI middleware: require a valid Bearer API key on all HTTP requests except /health."""

    def __init__(self, app: ASGIApp, key_store: APIKeyStore) -> None:
        self.app = app
        self._store = key_store

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Lifespan events are internal ASGI machinery — pass through unconditionally.
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return

        # WebSocket is not used by this server. Reject explicitly rather than
        # passing through unauthenticated.
        if scope["type"] == "websocket":
            client_host = scope.get("client", ("unknown", 0))[0]
            logger.warning("websocket connection rejected", extra={"client_host": client_host})
            await receive()  # consume the websocket.connect event
            await send({"type": "websocket.close", "code": 1008})
            return

        # HTTP — apply auth (except for exempted paths).
        path: str = scope.get("path", "")
        if path in _SKIP_PATHS:
            await self.app(scope, receive, send)
            return

        headers: dict[bytes, bytes] = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()
        m = _BEARER_RE.match(auth_header)
        if not m:
            client_host = scope.get("client", ("unknown", 0))[0]
            logger.warning(
                "unauthenticated request",
                extra={"path": path, "client_host": client_host},
            )
            response = JSONResponse(
                {
                    "error": True,
                    "code": "unauthorized",
                    "message": "Missing or invalid Authorization header",
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        token = m.group(1)
        identity = self._store.validate(token)
        if identity is None:
            client_host = scope.get("client", ("unknown", 0))[0]
            logger.warning(
                "invalid API key",
                extra={"path": path, "client_host": client_host},
            )
            response = JSONResponse(
                {"error": True, "code": "unauthorized", "message": "Invalid API key"},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        logger.debug(
            "authenticated request",
            extra={"path": path, "client_id": identity.client_id},
        )
        token_ref = _client_ctx.set(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            _client_ctx.reset(token_ref)
