"""Authorization policy engine."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

import yaml

from .auth import ClientIdentity

logger = logging.getLogger(__name__)


@dataclass
class ClientPolicy:
    """Per-client authorization policy."""

    allowed_tools: list[str]  # ["*"] = all tools allowed; [] = no tools allowed
    allowed_cidrs: list[str]  # ["*"] = all hosts allowed; [] = no scan targets allowed
    max_concurrent_scans: int = 0  # 0 = no limit


@dataclass
class Policy:
    """Loaded authorization policy."""

    clients: dict[str, ClientPolicy] = field(default_factory=dict)
    default_policy: ClientPolicy = field(
        default_factory=lambda: ClientPolicy(allowed_tools=["*"], allowed_cidrs=["*"])
    )

    def _get(self, identity: ClientIdentity | None) -> ClientPolicy:
        if identity is None:
            return self.default_policy
        return self.clients.get(identity.client_id, self.default_policy)

    def is_tool_allowed(self, tool: str, identity: ClientIdentity | None = None) -> bool:
        pol = self._get(identity)
        return "*" in pol.allowed_tools or tool in pol.allowed_tools

    def is_host_allowed(self, host: str, identity: ClientIdentity | None = None) -> bool:
        pol = self._get(identity)
        if "*" in pol.allowed_cidrs:
            return True
        if not pol.allowed_cidrs:
            return False
        host = host.strip()
        try:
            addr = ipaddress.ip_address(host)
            return any(
                addr in ipaddress.ip_network(cidr, strict=False) for cidr in pol.allowed_cidrs
            )
        except ValueError:
            pass
        try:
            net = ipaddress.ip_network(host, strict=False)
            return any(
                net.subnet_of(ipaddress.ip_network(cidr, strict=False))
                for cidr in pol.allowed_cidrs
            )
        except ValueError:
            pass
        # Hostname — not matched by CIDR rules, deny
        return False

    def max_concurrent_scans(self, identity: ClientIdentity | None = None) -> int:
        return self._get(identity).max_concurrent_scans


_policy: Policy = Policy()


def get_policy() -> Policy:
    return _policy


def set_policy(p: Policy) -> None:
    global _policy
    _policy = p


def load_policy(path: str | None) -> Policy:
    """Load policy from a YAML file, or return the permissive default if no path is given."""
    if not path:
        return Policy()
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("policy file not found, using permissive default", extra={"path": path})
        return Policy()
    except Exception as e:
        raise ValueError(f"Failed to load policy file {path!r}: {e}") from e

    clients: dict[str, ClientPolicy] = {}
    for client_id, cd in (data.get("clients") or {}).items():
        clients[client_id] = ClientPolicy(
            allowed_tools=cd.get("allowed_tools", ["*"]),
            allowed_cidrs=cd.get("allowed_cidrs", ["*"]),
            max_concurrent_scans=int(cd.get("max_concurrent_scans", 0)),
        )

    default_data = data.get("default") or {}
    default = ClientPolicy(
        allowed_tools=default_data.get("allowed_tools", ["*"]),
        allowed_cidrs=default_data.get("allowed_cidrs", ["*"]),
        max_concurrent_scans=int(default_data.get("max_concurrent_scans", 0)),
    )

    return Policy(clients=clients, default_policy=default)
