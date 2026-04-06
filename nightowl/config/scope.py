"""Scope management - ensures scans stay within authorized boundaries."""

import ipaddress
import logging

from nightowl.models.config import ScopeConfig
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class ScopeManager:
    """Validates targets against the configured scope."""

    def __init__(self, scope: ScopeConfig):
        self.scope = scope
        self._networks = []
        for net in scope.allowed_networks:
            try:
                self._networks.append(ipaddress.ip_network(net, strict=False))
            except ValueError:
                logger.warning(f"Invalid network in scope: {net}")

    def is_target_allowed(self, target: Target) -> bool:
        raw_host = target.host.strip()
        host = target.effective_host

        # Check exclusions first
        if raw_host in self.scope.excluded_hosts or host in self.scope.excluded_hosts:
            return False
        for excluded in self.scope.excluded_hosts:
            if excluded.startswith("*.") and (
                raw_host.endswith(excluded[1:]) or host.endswith(excluded[1:])
            ):
                return False

        # Check explicit hosts
        if raw_host in self.scope.allowed_hosts or host in self.scope.allowed_hosts:
            return True

        # Check wildcard domains
        for allowed in self.scope.allowed_hosts:
            if allowed.startswith("*.") and (
                raw_host.endswith(allowed[1:]) or host.endswith(allowed[1:])
            ):
                return True

        # Check explicit IPs
        if host in self.scope.allowed_ips or raw_host in self.scope.allowed_ips:
            return True

        # Check networks
        if target.target_type.value == "network":
            try:
                target_network = ipaddress.ip_network(raw_host, strict=False)
                for net in self._networks:
                    if target_network.subnet_of(net):
                        return True
            except ValueError:
                pass

        try:
            ip = ipaddress.ip_address(target.ip or host or raw_host)
            for net in self._networks:
                if ip in net:
                    return True
        except ValueError:
            pass

        # Deny by default — no scope = nothing allowed
        if (
            not self.scope.allowed_hosts
            and not self.scope.allowed_ips
            and not self.scope.allowed_networks
        ):
            logger.error(
                f"No scope defined — target '{raw_host}' denied. "
                "Define scope in config or use --scope flag."
            )
            return False

        return False

    @property
    def has_scope(self) -> bool:
        return bool(
            self.scope.allowed_hosts
            or self.scope.allowed_ips
            or self.scope.allowed_networks
        )

    def add_host(self, host: str) -> None:
        self.scope.allowed_hosts.append(host)

    def remove_host(self, host: str) -> None:
        self.scope.allowed_hosts = [h for h in self.scope.allowed_hosts if h != host]

    def add_network(self, network: str) -> None:
        self.scope.allowed_networks.append(network)
        try:
            self._networks.append(ipaddress.ip_network(network, strict=False))
        except ValueError:
            pass
