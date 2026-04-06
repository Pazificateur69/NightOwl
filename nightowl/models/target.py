"""Target models for scan targets."""

import fnmatch
import ipaddress
import re
from enum import Enum
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    NETWORK = "network"
    AD_DOMAIN = "ad_domain"
    UNKNOWN = "unknown"


class Target(BaseModel):
    """Represents a scan target."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    host: str
    ip: str | None = None
    port: int | None = None
    protocol: str = "tcp"
    url: str | None = None
    domain: str | None = None
    target_type: TargetType = TargetType.UNKNOWN
    scope_tags: list[str] = Field(default_factory=list)
    credentials: dict | None = None

    @model_validator(mode="after")
    def detect_target_type(self) -> "Target":
        host = self.host.strip()

        if host.startswith(("http://", "https://")):
            self.target_type = TargetType.URL
            self.url = host
            parsed = urlparse(host)
            self.domain = parsed.hostname
        elif "/" in host:
            try:
                ipaddress.ip_network(host, strict=False)
                self.target_type = TargetType.NETWORK
            except ValueError:
                self.target_type = TargetType.UNKNOWN
        else:
            try:
                ipaddress.ip_address(host)
                self.target_type = TargetType.IP
                self.ip = host
            except ValueError:
                if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", host):
                    self.target_type = TargetType.DOMAIN
                    self.domain = host
                else:
                    self.target_type = TargetType.UNKNOWN

        return self

    @property
    def effective_host(self) -> str:
        """The actual hostname/IP to use for scope checks."""
        if self.domain:
            return self.domain
        if self.ip:
            return self.ip
        return self.host.strip()

    def is_in_scope(
        self,
        allowed_hosts: list[str],
        allowed_ips: list[str] | None = None,
        allowed_networks: list[str] | None = None,
        excluded_hosts: list[str] | None = None,
    ) -> bool:
        """Check if this target matches the provided scope patterns."""
        host = self.effective_host

        for pattern in excluded_hosts or []:
            if fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(self.host.strip(), pattern):
                return False

        for pattern in allowed_hosts:
            if fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(self.host.strip(), pattern):
                return True

        if host in (allowed_ips or []):
            return True

        if self.target_type == TargetType.NETWORK:
            try:
                target_network = ipaddress.ip_network(self.host.strip(), strict=False)
                for network in allowed_networks or []:
                    try:
                        if target_network.subnet_of(ipaddress.ip_network(network, strict=False)):
                            return True
                    except ValueError:
                        continue
            except ValueError:
                pass

        if self.ip:
            ip = ipaddress.ip_address(self.ip)
            for network in allowed_networks or []:
                try:
                    if ip in ipaddress.ip_network(network, strict=False):
                        return True
                except ValueError:
                    continue

        return False
