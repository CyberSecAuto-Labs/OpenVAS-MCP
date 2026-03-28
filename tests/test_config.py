"""Tests for openvas_mcp.config."""

from __future__ import annotations

import pytest


def test_defaults(monkeypatch):
    monkeypatch.delenv("GVM_SOCKET_PATH", raising=False)
    monkeypatch.delenv("GVM_HOST", raising=False)
    monkeypatch.delenv("GVM_PORT", raising=False)
    monkeypatch.delenv("GVM_TLS", raising=False)
    monkeypatch.delenv("GVM_USERNAME", raising=False)
    monkeypatch.delenv("GVM_PASSWORD", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    from openvas_mcp.config import Config

    cfg = Config.from_env()
    assert cfg.socket_path == "/run/gvmd/gvmd.sock"
    assert cfg.host == ""
    assert cfg.port == 9390
    assert cfg.tls is False
    assert cfg.username == "admin"
    assert cfg.password == ""
    assert cfg.log_level == "INFO"


def test_gvm_port_invalid(monkeypatch):
    monkeypatch.setenv("GVM_PORT", "not-a-number")
    from openvas_mcp.config import Config

    with pytest.raises(ValueError, match="GVM_PORT must be an integer"):
        Config.from_env()


def test_log_level_invalid(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "VERBOSE")
    from openvas_mcp.config import Config

    with pytest.raises(ValueError, match="LOG_LEVEL must be one of"):
        Config.from_env()


@pytest.mark.parametrize("value", ["1", "true", "yes", "True", "YES"])
def test_tls_truthy_values(monkeypatch, value):
    monkeypatch.setenv("GVM_TLS", value)
    from openvas_mcp.config import Config

    cfg = Config.from_env()
    assert cfg.tls is True


def test_tls_falsy(monkeypatch):
    monkeypatch.setenv("GVM_TLS", "false")
    from openvas_mcp.config import Config

    cfg = Config.from_env()
    assert cfg.tls is False


def test_missing_required_no_password(monkeypatch, tmp_path):
    monkeypatch.setenv("GVM_SOCKET_PATH", str(tmp_path / "gvmd.sock"))
    monkeypatch.delenv("GVM_HOST", raising=False)
    monkeypatch.delenv("GVM_PASSWORD", raising=False)
    from openvas_mcp.config import Config

    cfg = Config.from_env()
    missing = cfg.missing_required()
    assert any("GVM_PASSWORD" in m for m in missing)


def test_missing_required_no_socket_no_host(monkeypatch, tmp_path):
    monkeypatch.setenv("GVM_SOCKET_PATH", str(tmp_path / "nonexistent.sock"))
    monkeypatch.delenv("GVM_HOST", raising=False)
    monkeypatch.setenv("GVM_PASSWORD", "secret")
    from openvas_mcp.config import Config

    cfg = Config.from_env()
    missing = cfg.missing_required()
    assert any("GVM_SOCKET_PATH" in m for m in missing)


def test_no_missing_when_host_and_password_set(monkeypatch):
    monkeypatch.setenv("GVM_HOST", "localhost")
    monkeypatch.setenv("GVM_PASSWORD", "secret")
    from openvas_mcp.config import Config

    cfg = Config.from_env()
    assert cfg.missing_required() == []
