"""Kerberos attack scanner (AS-REP Roasting, Kerberoasting)."""

import logging
import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

try:
    from impacket.krb5.asn1 import AS_REP
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


class KerberosPlugin(ScannerPlugin):
    name = "kerberos-scanner"
    description = "Kerberos AS-REP Roasting and Kerberoasting checks"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.ip or target.host
        creds = target.credentials or {}
        domain = creds.get("domain", "")

        if not HAS_IMPACKET:
            logger.warning("impacket not installed, skipping Kerberos scan")
            return findings

        if not domain:
            logger.info("No domain specified, skipping Kerberos scan")
            return findings

        # AS-REP Roasting
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal

            users = kwargs.get("users", []) or creds.get("users", [])
            if not users:
                users = ["administrator", "admin", "svc_sql", "svc_web", "backup", "krbtgt"]

            for username in users:
                try:
                    client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                    # Try to get TGT without preauth
                    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                        client_name, "", domain, None, None, None, host
                    )
                    if tgt:
                        findings.append(Finding(
                            title=f"AS-REP Roastable account: {username}",
                            severity=Severity.HIGH, cvss_score=7.5,
                            description=f"Account {username} does not require Kerberos pre-authentication",
                            evidence=f"Domain: {domain}\nUser: {username}\nDC: {host}\nAS-REP hash obtained",
                            remediation="Enable Kerberos pre-authentication for all accounts.",
                            category="kerberos",
                        ))
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

        except Exception as e:
            logger.debug(f"AS-REP roasting failed: {e}")

        # Kerberoasting
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGS

            user = creds.get("user")
            password = creds.get("password")
            if user and password:
                findings.append(Finding(
                    title="Kerberoasting: authenticated scan available",
                    severity=Severity.INFO,
                    description="With valid credentials, Kerberoasting can extract TGS hashes for SPN accounts",
                    evidence=f"Domain: {domain}\nDC: {host}\nAuthenticated as: {user}",
                    remediation="Use long, complex passwords for service accounts. Prefer gMSA accounts.",
                    category="kerberos",
                ))
        except Exception as e:
            logger.debug(f"Kerberoasting check failed: {e}")

        return findings
