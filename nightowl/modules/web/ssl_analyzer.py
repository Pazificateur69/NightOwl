"""SSL/TLS analyzer plugin."""

import logging
import socket
import ssl
from datetime import datetime, timezone

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class SSLAnalyzerPlugin(ScannerPlugin):
    name = "ssl-analyzer"
    description = "Analyze SSL/TLS configuration and certificates"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.domain or target.host
        port = target.port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()

            # Check protocol version
            if version and "TLSv1.0" in version or "TLSv1.1" in version or "SSLv" in str(version):
                findings.append(Finding(
                    title=f"Weak TLS version: {version}",
                    severity=Severity.HIGH,
                    cvss_score=5.9,
                    description=f"Server supports deprecated protocol {version}",
                    evidence=f"Protocol: {version}",
                    remediation="Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2 or TLS 1.3 only.",
                    category="ssl",
                ))

            # Check cipher
            if cipher:
                cipher_name = cipher[0]
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
                for weak in weak_ciphers:
                    if weak in cipher_name.upper():
                        findings.append(Finding(
                            title=f"Weak cipher suite: {cipher_name}",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            evidence=f"Cipher: {cipher_name}",
                            remediation="Disable weak cipher suites. Use AES-GCM or ChaCha20.",
                            category="ssl",
                        ))

            # Check certificate
            if cert:
                # Expiry
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.now()).days
                        if days_left < 0:
                            findings.append(Finding(
                                title="SSL certificate expired",
                                severity=Severity.HIGH, cvss_score=5.9,
                                evidence=f"Expired: {not_after} ({abs(days_left)} days ago)",
                                remediation="Renew the SSL certificate immediately.",
                                category="ssl",
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                title=f"SSL certificate expires in {days_left} days",
                                severity=Severity.MEDIUM, cvss_score=3.7,
                                evidence=f"Expires: {not_after}",
                                remediation="Renew the certificate before expiration.",
                                category="ssl",
                            ))
                    except ValueError:
                        pass

                # Self-signed check
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                if issuer == subject:
                    findings.append(Finding(
                        title="Self-signed SSL certificate",
                        severity=Severity.MEDIUM, cvss_score=4.3,
                        evidence=f"Issuer and Subject match: {issuer.get('commonName', 'N/A')}",
                        remediation="Use a certificate from a trusted Certificate Authority.",
                        category="ssl",
                    ))

            if not findings:
                findings.append(Finding(
                    title=f"SSL/TLS configuration OK ({version})",
                    severity=Severity.INFO,
                    evidence=f"Protocol: {version}\nCipher: {cipher[0] if cipher else 'N/A'}",
                    category="ssl",
                ))

        except Exception as e:
            logger.warning(f"SSL analysis failed for {host}:{port}: {e}")

        return findings
