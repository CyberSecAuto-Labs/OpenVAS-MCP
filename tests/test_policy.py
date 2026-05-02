"""Tests for openvas_mcp.policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from openvas_mcp.auth import ClientIdentity
from openvas_mcp.policy import ClientPolicy, Policy, get_policy, load_policy, set_policy

FIXTURES = Path(__file__).parent / "fixtures"


class TestPolicyToolAllowance:
    def test_wildcard_allows_all_tools(self):
        p = Policy()
        assert p.is_tool_allowed("any_tool") is True
        assert p.is_tool_allowed("create_target") is True

    def test_explicit_allow_list(self):
        pol = ClientPolicy(allowed_tools=["list_tasks", "get_scan_status"], allowed_cidrs=["*"])
        p = Policy(clients={"alice": pol})
        identity = ClientIdentity(client_id="alice")
        assert p.is_tool_allowed("list_tasks", identity) is True
        assert p.is_tool_allowed("start_scan", identity) is False

    def test_empty_allowed_tools_denies_all(self):
        pol = ClientPolicy(allowed_tools=[], allowed_cidrs=["*"])
        p = Policy(clients={"alice": pol})
        identity = ClientIdentity(client_id="alice")
        assert p.is_tool_allowed("list_tasks", identity) is False

    def test_unknown_client_falls_back_to_default(self):
        p = Policy()
        identity = ClientIdentity(client_id="unknown")
        assert p.is_tool_allowed("create_target", identity) is True

    def test_none_identity_uses_default(self):
        p = Policy()
        assert p.is_tool_allowed("create_target", None) is True


class TestPolicyHostAllowance:
    def test_wildcard_allows_all_hosts(self):
        p = Policy()
        assert p.is_host_allowed("192.168.1.1") is True
        assert p.is_host_allowed("10.0.0.0/8") is True
        assert p.is_host_allowed("myhost.example.com") is True

    def test_ip_within_allowed_cidr(self):
        pol = ClientPolicy(allowed_tools=["*"], allowed_cidrs=["10.0.0.0/8"])
        p = Policy(clients={"alice": pol})
        identity = ClientIdentity(client_id="alice")
        assert p.is_host_allowed("10.1.2.3", identity) is True
        assert p.is_host_allowed("192.168.1.1", identity) is False

    def test_subnet_within_allowed_cidr(self):
        pol = ClientPolicy(allowed_tools=["*"], allowed_cidrs=["10.0.0.0/8"])
        p = Policy(clients={"alice": pol})
        identity = ClientIdentity(client_id="alice")
        assert p.is_host_allowed("10.1.0.0/16", identity) is True
        assert p.is_host_allowed("192.168.0.0/24", identity) is False

    def test_hostname_denied_when_cidrs_configured(self):
        pol = ClientPolicy(allowed_tools=["*"], allowed_cidrs=["10.0.0.0/8"])
        p = Policy(clients={"alice": pol})
        identity = ClientIdentity(client_id="alice")
        assert p.is_host_allowed("myhost.example.com", identity) is False

    def test_empty_cidrs_denies_all_hosts(self):
        pol = ClientPolicy(allowed_tools=["*"], allowed_cidrs=[])
        p = Policy(clients={"alice": pol})
        identity = ClientIdentity(client_id="alice")
        assert p.is_host_allowed("10.0.0.1", identity) is False

    def test_multiple_cidrs_any_match_allows(self):
        pol = ClientPolicy(allowed_tools=["*"], allowed_cidrs=["10.0.0.0/8", "192.168.0.0/16"])
        p = Policy(clients={"alice": pol})
        identity = ClientIdentity(client_id="alice")
        assert p.is_host_allowed("10.5.0.1", identity) is True
        assert p.is_host_allowed("192.168.1.100", identity) is True
        assert p.is_host_allowed("172.16.0.1", identity) is False


class TestPolicyMaxConcurrentScans:
    def test_default_is_zero(self):
        p = Policy()
        assert p.max_concurrent_scans() == 0
        assert p.max_concurrent_scans(None) == 0

    def test_per_client_limit(self):
        pol = ClientPolicy(allowed_tools=["*"], allowed_cidrs=["*"], max_concurrent_scans=3)
        p = Policy(clients={"alice": pol})
        assert p.max_concurrent_scans(ClientIdentity(client_id="alice")) == 3
        assert p.max_concurrent_scans(ClientIdentity(client_id="other")) == 0


class TestLoadPolicy:
    def test_no_path_returns_permissive_policy(self):
        p = load_policy(None)
        assert p.is_tool_allowed("any_tool") is True
        assert p.is_host_allowed("1.2.3.4") is True

    def test_missing_file_raises(self):
        with pytest.raises(ValueError, match="Policy file not found"):
            load_policy(str(FIXTURES / "nonexistent.yaml"))

    def test_loads_clients_from_yaml(self):
        p = load_policy(str(FIXTURES / "policy_clients.yaml"))
        alice = ClientIdentity(client_id="alice")
        admin = ClientIdentity(client_id="admin")
        assert p.is_tool_allowed("list_tasks", alice) is True
        assert p.is_tool_allowed("start_scan", alice) is False
        assert p.is_tool_allowed("start_scan", admin) is True
        assert p.is_host_allowed("10.5.0.1", alice) is True
        assert p.is_host_allowed("192.168.1.1", alice) is False

    def test_loads_default_block_from_yaml(self):
        p = load_policy(str(FIXTURES / "policy_default_only.yaml"))
        unknown = ClientIdentity(client_id="unknown")
        assert p.is_tool_allowed("list_tasks", unknown) is True
        assert p.is_tool_allowed("start_scan", unknown) is False

    def test_invalid_yaml_raises_value_error(self):
        with pytest.raises(ValueError, match="Failed to load policy file"):
            load_policy(str(FIXTURES / "policy_invalid.yaml"))

    def test_max_concurrent_scans_loaded_from_yaml(self):
        p = load_policy(str(FIXTURES / "policy_max_scans.yaml"))
        assert p.max_concurrent_scans(ClientIdentity(client_id="alice")) == 2
        assert p.max_concurrent_scans(None) == 0


class TestGetSetPolicy:
    def test_set_policy_replaces_global(self):
        original = get_policy()
        new_policy = Policy(default_policy=ClientPolicy(allowed_tools=[], allowed_cidrs=[]))
        set_policy(new_policy)
        try:
            assert get_policy().is_tool_allowed("list_tasks") is False
        finally:
            set_policy(original)
