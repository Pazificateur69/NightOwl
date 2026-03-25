"""SMB enumeration plugin."""

import logging
import socket

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

try:
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


class SMBEnumPlugin(ScannerPlugin):
    name = "smb-enum"
    description = "Enumerate SMB shares and check anonymous access"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.ip or target.host
        port = target.port or 445

        # Check port open first
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
        except Exception:
            return findings

        if not HAS_IMPACKET:
            findings.append(Finding(
                title=f"SMB port open on {host}:{port}",
                severity=Severity.INFO,
                description="SMB port is open. Install impacket for full enumeration.",
                evidence=f"Port {port} is open. impacket not installed.",
                category="smb",
            ))
            return findings

        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=10)

            # Try anonymous login
            try:
                conn.login("", "")
                findings.append(Finding(
                    title=f"SMB anonymous login allowed on {host}",
                    severity=Severity.HIGH, cvss_score=7.5,
                    description="SMB allows anonymous/null session authentication",
                    evidence=f"Connected to {host}:{port} with empty credentials",
                    remediation="Disable anonymous SMB access. Require authentication for all connections.",
                    category="smb",
                ))

                # Enumerate shares
                try:
                    shares = conn.listShares()
                    for share in shares:
                        name = share["shi1_netname"][:-1]
                        remark = share["shi1_remark"][:-1] if share["shi1_remark"] else ""
                        findings.append(Finding(
                            title=f"SMB share: {name}",
                            severity=Severity.MEDIUM,
                            description=f"Accessible SMB share: {name} ({remark})",
                            evidence=f"Share: {name}\nRemark: {remark}",
                            category="smb",
                        ))
                except Exception as e:
                    logger.debug(f"Share enumeration failed: {e}")

            except Exception:
                findings.append(Finding(
                    title=f"SMB requires authentication on {host}",
                    severity=Severity.INFO,
                    evidence=f"Anonymous login rejected on {host}:{port}",
                    category="smb",
                ))

            conn.close()

        except Exception as e:
            logger.warning(f"SMB enum failed for {host}: {e}")

        return findings
