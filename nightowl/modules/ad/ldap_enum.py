"""LDAP enumeration plugin for Active Directory."""

import logging

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

try:
    from ldap3 import ALL, Connection, Server, ANONYMOUS, SUBTREE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


class LDAPEnumPlugin(ScannerPlugin):
    name = "ldap-enum"
    description = "Enumerate LDAP directory (users, groups, OUs)"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.ip or target.host
        creds = target.credentials or {}

        if not HAS_LDAP3:
            logger.warning("ldap3 not installed, skipping LDAP enumeration")
            return findings

        try:
            server = Server(host, port=389, get_info=ALL, connect_timeout=10)

            # Try anonymous bind first
            user = creds.get("user")
            password = creds.get("password")
            domain = creds.get("domain", "")

            if user and password:
                bind_dn = f"{domain}\\{user}" if domain else user
                conn = Connection(server, user=bind_dn, password=password, auto_bind=True)
            else:
                conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)

            # Get base DN
            base_dn = ""
            if server.info and server.info.naming_contexts:
                base_dn = str(server.info.naming_contexts[0])

                findings.append(Finding(
                    title=f"LDAP base DN: {base_dn}",
                    severity=Severity.INFO,
                    evidence=f"Naming contexts: {server.info.naming_contexts}",
                    category="ldap",
                ))

            if not base_dn:
                conn.unbind()
                return findings

            # Enumerate users
            conn.search(base_dn, "(objectClass=person)", search_scope=SUBTREE,
                       attributes=["sAMAccountName", "cn", "mail", "memberOf"], size_limit=100)
            users = []
            for entry in conn.entries:
                sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else str(entry.cn)
                users.append(sam)

            if users:
                findings.append(Finding(
                    title=f"LDAP users enumerated: {len(users)} found",
                    severity=Severity.MEDIUM, cvss_score=5.3,
                    description="User accounts enumerated via LDAP",
                    evidence="\n".join(users[:50]),
                    remediation="Restrict anonymous LDAP queries. Limit information exposed via LDAP.",
                    category="ldap",
                    metadata={"users": users},
                ))

            # Enumerate groups
            conn.search(base_dn, "(objectClass=group)", search_scope=SUBTREE,
                       attributes=["cn", "member"], size_limit=50)
            groups = [str(e.cn) for e in conn.entries]
            if groups:
                findings.append(Finding(
                    title=f"LDAP groups enumerated: {len(groups)} found",
                    severity=Severity.INFO,
                    evidence="\n".join(groups[:30]),
                    category="ldap",
                    metadata={"groups": groups},
                ))

            conn.unbind()

        except Exception as e:
            logger.warning(f"LDAP enum failed for {host}: {e}")

        return findings
