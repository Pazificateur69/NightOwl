"""SSH configuration audit plugin."""

import logging

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

WEAK_KEXS = {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "3des-cbc", "cast128-cbc"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96"}


class SSHAuditPlugin(ScannerPlugin):
    name = "ssh-audit"
    description = "Audit SSH server configuration for weak algorithms"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.ip or target.host
        port = target.port or 22

        if not HAS_PARAMIKO:
            logger.warning("paramiko not installed, skipping SSH audit")
            return findings

        try:
            transport = paramiko.Transport((host, port))
            transport.connect()

            # Get banner
            banner = transport.remote_version or "Unknown"
            findings.append(Finding(
                title=f"SSH banner: {banner}",
                severity=Severity.INFO,
                evidence=f"Host: {host}:{port}\nBanner: {banner}",
                category="ssh",
            ))

            # Check algorithms
            sec_opts = transport.get_security_options()

            weak_kex = set(sec_opts.kex) & WEAK_KEXS
            if weak_kex:
                findings.append(Finding(
                    title="Weak SSH key exchange algorithms",
                    severity=Severity.MEDIUM, cvss_score=5.3,
                    description="Server supports weak key exchange algorithms",
                    evidence=f"Weak KEX: {', '.join(weak_kex)}",
                    remediation="Disable weak key exchange algorithms. Use curve25519-sha256 or ecdh-sha2-nistp256.",
                    category="ssh",
                ))

            weak_enc = set(sec_opts.ciphers) & WEAK_CIPHERS
            if weak_enc:
                findings.append(Finding(
                    title="Weak SSH ciphers",
                    severity=Severity.MEDIUM, cvss_score=5.3,
                    evidence=f"Weak ciphers: {', '.join(weak_enc)}",
                    remediation="Disable weak ciphers. Use aes256-gcm@openssh.com or chacha20-poly1305.",
                    category="ssh",
                ))

            weak_mac = set(sec_opts.digests) & WEAK_MACS
            if weak_mac:
                findings.append(Finding(
                    title="Weak SSH MAC algorithms",
                    severity=Severity.LOW, cvss_score=3.7,
                    evidence=f"Weak MACs: {', '.join(weak_mac)}",
                    remediation="Disable weak MAC algorithms. Use hmac-sha2-256-etm@openssh.com.",
                    category="ssh",
                ))

            transport.close()

        except Exception as e:
            logger.warning(f"SSH audit failed for {host}:{port}: {e}")

        return findings
