"""Tests for openvas_mcp.auth."""

from __future__ import annotations

from starlette.testclient import TestClient

from openvas_mcp.auth import (
    APIKeyStore,
    AuthMiddleware,
    ClientIdentity,
    _RateLimiter,
    _client_ctx,
    get_current_client,
)


class TestAPIKeyStore:
    def test_validate_valid_key(self):
        store = APIKeyStore("tok1:alice,tok2:bob")
        assert store.validate("tok1") == ClientIdentity(client_id="alice")
        assert store.validate("tok2") == ClientIdentity(client_id="bob")

    def test_validate_invalid_key(self):
        store = APIKeyStore("tok1:alice")
        assert store.validate("bad") is None

    def test_key_without_name_uses_token_as_id(self):
        store = APIKeyStore("mytoken")
        assert store.validate("mytoken") == ClientIdentity(client_id="mytoken")

    def test_is_empty_when_empty_string(self):
        assert APIKeyStore("").is_empty

    def test_is_empty_when_whitespace(self):
        assert APIKeyStore("   ").is_empty

    def test_is_not_empty_when_has_keys(self):
        assert not APIKeyStore("tok1:alice").is_empty

    def test_ignores_empty_entries(self):
        store = APIKeyStore("tok1:alice,,tok2:bob,")
        assert store.validate("tok1") == ClientIdentity(client_id="alice")
        assert store.validate("tok2") == ClientIdentity(client_id="bob")


class TestGetCurrentClient:
    def test_returns_none_by_default(self):
        assert get_current_client() is None

    def test_returns_identity_when_context_var_is_set(self):
        identity = ClientIdentity(client_id="alice")
        token = _client_ctx.set(identity)
        try:
            assert get_current_client() == identity
        finally:
            _client_ctx.reset(token)


def _make_echo_app():
    async def _app(scope, receive, send):
        from starlette.responses import PlainTextResponse

        await PlainTextResponse("ok")(scope, receive, send)

    return _app


class TestAuthMiddleware:
    def test_missing_auth_header_returns_401(self):
        app = AuthMiddleware(_make_echo_app(), key_store=APIKeyStore("tok1:alice"))
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/some/path")
        assert response.status_code == 401
        assert response.json()["code"] == "unauthorized"

    def test_malformed_auth_header_returns_401(self):
        app = AuthMiddleware(_make_echo_app(), key_store=APIKeyStore("tok1:alice"))
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/some/path", headers={"Authorization": "Basic tok1"})
        assert response.status_code == 401

    def test_invalid_api_key_returns_401(self):
        app = AuthMiddleware(_make_echo_app(), key_store=APIKeyStore("tok1:alice"))
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/some/path", headers={"Authorization": "Bearer badtoken"})
        assert response.status_code == 401
        assert response.json()["code"] == "unauthorized"

    def test_valid_api_key_passes_through(self):
        app = AuthMiddleware(_make_echo_app(), key_store=APIKeyStore("tok1:alice"))
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/some/path", headers={"Authorization": "Bearer tok1"})
        assert response.status_code == 200

    def test_health_endpoint_skips_auth(self):
        app = AuthMiddleware(_make_echo_app(), key_store=APIKeyStore("tok1:alice"))
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/health")
        assert response.status_code == 200

    def test_bearer_token_case_insensitive(self):
        app = AuthMiddleware(_make_echo_app(), key_store=APIKeyStore("tok1:alice"))
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/some/path", headers={"Authorization": "bearer tok1"})
        assert response.status_code == 200

    def test_websocket_connection_rejected(self):
        import pytest
        from starlette.websockets import WebSocketDisconnect

        app = AuthMiddleware(_make_echo_app(), key_store=APIKeyStore("tok1:alice"))
        client = TestClient(app, raise_server_exceptions=False)
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass
        assert exc_info.value.code == 1008

    def test_constant_time_comparison_accepts_valid_token(self):
        store = APIKeyStore("abc123:alice,def456:bob")
        assert store.validate("abc123") == ClientIdentity(client_id="alice")
        assert store.validate("def456") == ClientIdentity(client_id="bob")

    def test_constant_time_comparison_rejects_invalid_token(self):
        store = APIKeyStore("abc123:alice")
        assert store.validate("abc124") is None
        assert store.validate("") is None
        assert store.validate("abc123extra") is None


class TestRateLimiter:
    def test_not_blocked_initially(self):
        limiter = _RateLimiter(max_attempts=3, window=60.0)
        assert not limiter.is_blocked("1.2.3.4")

    def test_blocked_after_max_failures(self):
        limiter = _RateLimiter(max_attempts=3, window=60.0)
        for _ in range(3):
            limiter.record_failure("1.2.3.4")
        assert limiter.is_blocked("1.2.3.4")

    def test_not_blocked_below_max_failures(self):
        limiter = _RateLimiter(max_attempts=3, window=60.0)
        limiter.record_failure("1.2.3.4")
        limiter.record_failure("1.2.3.4")
        assert not limiter.is_blocked("1.2.3.4")

    def test_success_clears_failures(self):
        limiter = _RateLimiter(max_attempts=3, window=60.0)
        for _ in range(3):
            limiter.record_failure("1.2.3.4")
        assert limiter.is_blocked("1.2.3.4")
        limiter.record_success("1.2.3.4")
        assert not limiter.is_blocked("1.2.3.4")

    def test_failures_expire_after_window(self):
        import time

        limiter = _RateLimiter(max_attempts=3, window=0.05)
        for _ in range(3):
            limiter.record_failure("1.2.3.4")
        assert limiter.is_blocked("1.2.3.4")
        time.sleep(0.1)
        assert not limiter.is_blocked("1.2.3.4")

    def test_independent_tracking_per_ip(self):
        limiter = _RateLimiter(max_attempts=3, window=60.0)
        for _ in range(3):
            limiter.record_failure("1.2.3.4")
        assert limiter.is_blocked("1.2.3.4")
        assert not limiter.is_blocked("5.6.7.8")

    def test_oldest_ip_evicted_when_cap_reached(self):
        limiter = _RateLimiter(max_attempts=3, window=60.0, max_ips=2)
        limiter.record_failure("1.1.1.1")
        limiter.record_failure("2.2.2.2")
        # Adding a third IP should evict the oldest (1.1.1.1)
        limiter.record_failure("3.3.3.3")
        assert "1.1.1.1" not in limiter._failures
        assert "2.2.2.2" in limiter._failures
        assert "3.3.3.3" in limiter._failures

    def test_middleware_returns_429_after_max_failures(self):
        app = AuthMiddleware(_make_echo_app(), key_store=APIKeyStore("tok1:alice"))
        # Exhaust the default limit via the middleware directly
        app._limiter = _RateLimiter(max_attempts=3, window=60.0)
        client = TestClient(app, raise_server_exceptions=False)
        for _ in range(3):
            client.get("/path")  # no auth header → record_failure
        response = client.get("/path")
        assert response.status_code == 429
        assert response.json()["code"] == "rate_limited"
        assert "Retry-After" in response.headers
