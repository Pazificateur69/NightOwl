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
        host = target.host.strip()

        # Check exclusions first
        if host in self.scope.excluded_hosts:
            return False
        for excluded in self.scope.excluded_hosts:
            if excluded.startswith("*.") and host.endswith(excluded[1:]):
                return False

        # Check explicit hosts
        if host in self.scope.allowed_hosts:
            return True

        # Check wildcard domains
        for allowed in self.scope.allowed_hosts:
            if allowed.startswith("*.") and host.endswith(allowed[1:]):
                return True

        # Check explicit IPs
        if host in self.scope.allowed_ips:
            return True

        # Check networks
        try:
            ip = ipaddress.ip_address(target.ip or host)
            for net in self._networks:
                if ip in net:
                    return True
        except ValueError:
            pass

        # If no scope defined, allow everything (with warning)
        if (
            not self.scope.allowed_hosts
            and not self.scope.allowed_ips
            and not self.scope.allowed_networks
        ):
            logger.warning(f"No scope defined, allowing {host}")
            return True

        return False

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
