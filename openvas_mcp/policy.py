"""Authorization policy engine."""

from __future__ import annotations

import fnmatch
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

        # Try to parse as an IP address (single host).
        try:
            addr = ipaddress.ip_address(host)
            # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:10.0.0.1 → 10.0.0.1) so it
            # matches IPv4 CIDR rules correctly.
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            for entry in pol.allowed_cidrs:
                try:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                except (ValueError, TypeError):
                    pass
            return False
        except ValueError:
            pass

        # Try to parse as a CIDR range (the host argument is itself a range).
        try:
            net = ipaddress.ip_network(host, strict=False)
            for entry in pol.allowed_cidrs:
                try:
                    if net.subnet_of(ipaddress.ip_network(entry, strict=False)):  # type: ignore[arg-type]
                        return True
                except (ValueError, TypeError):
                    pass
            return False
        except ValueError:
            pass

        # Hostname — match against any non-CIDR entries in allowed_cidrs using
        # fnmatch so operators can write e.g. "*.internal" or "db.prod".
        for entry in pol.allowed_cidrs:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                if fnmatch.fnmatch(host.lower(), entry.lower()):
                    return True
        return False

    def max_concurrent_scans(self, identity: ClientIdentity | None = None) -> int:
        return self._get(identity).max_concurrent_scans


_policy: Policy = Policy()


def get_policy() -> Policy:
    return _policy


def set_policy(p: Policy) -> None:
    global _policy
    _policy = p


def _parse_max_scans(value: object) -> int:
    """Parse max_concurrent_scans from a YAML value, rejecting non-integer types."""
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"max_concurrent_scans must be a whole number, got: {value!r}")
    if not isinstance(value, (int, float)):
        raise ValueError(f"max_concurrent_scans must be a number, got: {value!r}")
    return int(value)


def load_policy(path: str | None, known_tools: frozenset[str] | None = None) -> Policy:
    """Load policy from a YAML file, or return the permissive default if no path is given."""
    if not path:
        return Policy()
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        raise ValueError(f"Policy file not found: {path!r}") from None
    except Exception as e:
        raise ValueError(f"Failed to load policy file {path!r}: {e}") from e

    clients: dict[str, ClientPolicy] = {}
    for client_id, cd in (data.get("clients") or {}).items():
        clients[client_id] = ClientPolicy(
            allowed_tools=cd.get("allowed_tools", ["*"]),
            allowed_cidrs=cd.get("allowed_cidrs", ["*"]),
            max_concurrent_scans=_parse_max_scans(cd.get("max_concurrent_scans", 0)),
        )

    default_data = data.get("default") or {}
    default = ClientPolicy(
        allowed_tools=default_data.get("allowed_tools", ["*"]),
        allowed_cidrs=default_data.get("allowed_cidrs", ["*"]),
        max_concurrent_scans=_parse_max_scans(default_data.get("max_concurrent_scans", 0)),
    )

    policy = Policy(clients=clients, default_policy=default)

    if known_tools is not None:
        all_tool_entries: list[str] = []
        for cp in list(clients.values()) + [default]:
            all_tool_entries.extend(cp.allowed_tools)
        for tool in all_tool_entries:
            if tool != "*" and tool not in known_tools:
                logger.warning(
                    "unknown tool name in policy — entry will never match",
                    extra={"tool": tool, "known_tools": sorted(known_tools)},
                )

    return policy
