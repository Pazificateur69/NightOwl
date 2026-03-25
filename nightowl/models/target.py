"""Target models for scan targets."""

import ipaddress
import re
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    NETWORK = "network"
    AD_DOMAIN = "ad_domain"


class Target(BaseModel):
    """Represents a scan target."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    host: str
    ip: str | None = None
    port: int | None = None
    protocol: str = "tcp"
    url: str | None = None
    domain: str | None = None
    target_type: TargetType = TargetType.IP
    scope_tags: list[str] = Field(default_factory=list)
    credentials: dict | None = None

    @model_validator(mode="after")
    def detect_target_type(self) -> "Target":
        host = self.host.strip()

        if host.startswith(("http://", "https://")):
            self.target_type = TargetType.URL
            self.url = host
        elif "/" in host:
            try:
                ipaddress.ip_network(host, strict=False)
                self.target_type = TargetType.NETWORK
            except ValueError:
                pass
        else:
            try:
                ipaddress.ip_address(host)
                self.target_type = TargetType.IP
                self.ip = host
            except ValueError:
                if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", host):
                    self.target_type = TargetType.DOMAIN
                    self.domain = host

        return self

    def is_in_scope(self, allowed_hosts: list[str], allowed_networks: list[str] | None = None) -> bool:
        if self.host in allowed_hosts:
            return True

        for pattern in allowed_hosts:
            if pattern.startswith("*.") and self.host.endswith(pattern[1:]):
                return True

        if self.ip and allowed_networks:
            ip = ipaddress.ip_address(self.ip)
            for net in allowed_networks:
                try:
                    if ip in ipaddress.ip_network(net, strict=False):
                        return True
                except ValueError:
                    continue

        return False
