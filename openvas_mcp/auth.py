"""API-key authentication for HTTP transports."""

from __future__ import annotations

import collections
import contextvars
import hmac
import logging
import re
import time
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
            if name and ":" in name:
                logger.warning(
                    "API key entry contains multiple colons; "
                    "token is the substring before the first colon — "
                    "verify that MCP_API_KEYS uses the 'token:name' format"
                )
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
# /health is intentionally unauthenticated for load-balancer compatibility;
# it returns only {"status": "ok"} with no sensitive information.
_SKIP_PATHS = frozenset({"/health"})

_RATE_LIMIT_ATTEMPTS = 10   # max failed auth attempts per window per IP
_RATE_LIMIT_WINDOW = 60.0   # seconds
_RATE_LIMIT_MAX_IPS = 10000  # max distinct IPs tracked; oldest evicted when exceeded


class _RateLimiter:
    """In-memory sliding-window rate limiter for failed authentication attempts."""

    def __init__(
        self,
        max_attempts: int = _RATE_LIMIT_ATTEMPTS,
        window: float = _RATE_LIMIT_WINDOW,
        max_ips: int = _RATE_LIMIT_MAX_IPS,
    ) -> None:
        self._max = max_attempts
        self._window = window
        self._max_ips = max_ips
        # ip → deque of timestamps of recent failed attempts (insertion-ordered)
        self._failures: dict[str, collections.deque[float]] = {}

    def is_blocked(self, ip: str) -> bool:
        self._evict(ip)
        return len(self._failures.get(ip, [])) >= self._max

    def record_failure(self, ip: str) -> None:
        if ip not in self._failures:
            if len(self._failures) >= self._max_ips:
                # Evict the oldest entry to bound memory usage.
                self._failures.pop(next(iter(self._failures)))
            self._failures[ip] = collections.deque()
        self._failures[ip].append(time.monotonic())

    def record_success(self, ip: str) -> None:
        self._failures.pop(ip, None)

    def _evict(self, ip: str) -> None:
        dq = self._failures.get(ip)
        if not dq:
            return
        cutoff = time.monotonic() - self._window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if not dq:
            del self._failures[ip]


class AuthMiddleware:
    """Pure ASGI middleware: require a valid Bearer API key on all HTTP requests except /health."""

    def __init__(self, app: ASGIApp, key_store: APIKeyStore) -> None:
        self.app = app
        self._store = key_store
        self._limiter = _RateLimiter()

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

        client_host = scope.get("client", ("unknown", 0))[0]

        if self._limiter.is_blocked(client_host):
            logger.warning(
                "rate limited",
                extra={"path": path, "client_host": client_host},
            )
            response = JSONResponse(
                {"error": True, "code": "rate_limited", "message": "Too many failed authentication attempts"},
                status_code=429,
                headers={"Retry-After": str(int(_RATE_LIMIT_WINDOW))},
            )
            await response(scope, receive, send)
            return

        headers: dict[bytes, bytes] = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()
        m = _BEARER_RE.match(auth_header)
        if not m:
            self._limiter.record_failure(client_host)
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
            self._limiter.record_failure(client_host)
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

        self._limiter.record_success(client_host)

        logger.debug(
            "authenticated request",
            extra={"path": path, "client_id": identity.client_id},
        )
        token_ref = _client_ctx.set(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            _client_ctx.reset(token_ref)
