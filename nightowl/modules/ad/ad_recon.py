"""Active Directory reconnaissance plugin."""

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


class ADReconPlugin(ScannerPlugin):
    name = "ad-recon"
    description = "Active Directory domain reconnaissance"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.ip or target.host
        creds = target.credentials or {}

        if not HAS_LDAP3:
            logger.warning("ldap3 not installed, skipping AD recon")
            return findings

        try:
            server = Server(host, port=389, get_info=ALL, connect_timeout=10)
            user = creds.get("user")
            password = creds.get("password")
            domain = creds.get("domain", "")

            if user and password:
                conn = Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True)
            else:
                conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)

            info = server.info

            # Domain info
            if info:
                details = []
                if info.naming_contexts:
                    details.append(f"Naming Contexts: {info.naming_contexts}")
                if hasattr(info, "supported_ldap_versions"):
                    details.append(f"LDAP Versions: {info.supported_ldap_versions}")
                if hasattr(info, "supported_sasl_mechanisms"):
                    details.append(f"SASL Mechanisms: {info.supported_sasl_mechanisms}")

                findings.append(Finding(
                    title=f"AD Domain info for {host}",
                    severity=Severity.INFO,
                    evidence="\n".join(details),
                    category="ad-recon",
                ))

            # Password policy
            base_dn = str(info.naming_contexts[0]) if info and info.naming_contexts else ""
            if base_dn:
                conn.search(base_dn, "(objectClass=domain)", attributes=[
                    "minPwdLength", "maxPwdAge", "lockoutThreshold", "lockoutDuration",
                    "pwdHistoryLength", "ms-DS-MachineAccountQuota"
                ])
                if conn.entries:
                    entry = conn.entries[0]
                    policy = str(entry)
                    findings.append(Finding(
                        title="AD Password Policy",
                        severity=Severity.INFO,
                        evidence=policy[:1000],
                        category="ad-recon",
                        metadata={"password_policy": policy},
                    ))

                    # Weak policy detection
                    min_len = getattr(entry, "minPwdLength", None)
                    if min_len and int(str(min_len)) < 8:
                        findings.append(Finding(
                            title=f"Weak password policy: minimum length {min_len}",
                            severity=Severity.MEDIUM, cvss_score=5.3,
                            evidence=f"Minimum password length: {min_len}",
                            remediation="Set minimum password length to at least 12 characters.",
                            category="ad-recon",
                        ))

            conn.unbind()

        except Exception as e:
            logger.warning(f"AD recon failed for {host}: {e}")

        return findings
