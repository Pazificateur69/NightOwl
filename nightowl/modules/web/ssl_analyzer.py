"""SSL/TLS analyzer plugin."""

import logging
import socket
import ssl
from datetime import datetime, timezone

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, FindingState, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class SSLAnalyzerPlugin(ScannerPlugin):
    name = "ssl-analyzer"
    description = "Analyze SSL/TLS configuration and certificates"
    version = "1.0.0"
    stage = "scan"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.connect_timeout: float = float(self.config.get("connect_timeout", self.timeout))

    @staticmethod
    def _is_weak_protocol(version: str | None) -> bool:
        if not version:
            return False
        upper = version.upper()
        return "TLSV1.0" in upper or "TLSV1.1" in upper or "SSLV" in upper

    @staticmethod
    def _parse_cert_date(date_str: str) -> datetime | None:
        """Parse certificate date with multiple format attempts."""
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y%m%d%H%M%SZ",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        # Last resort: try ssl.cert_time_to_seconds if available
        try:
            ts = ssl.cert_time_to_seconds(date_str)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            return None

    @staticmethod
    def _is_tls_port_open(host: str, port: int, timeout: float) -> bool:
        """Check if a port is open and accepting connections before TLS handshake."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.domain or target.host
        port = target.port or 443

        # Determine scheme from target.url or host
        raw = target.url or target.host
        if "://" in raw:
            from urllib.parse import urlparse as _urlparse
            parsed = _urlparse(raw)
            host = parsed.hostname or host
            if parsed.port:
                port = parsed.port
            # Plain HTTP targets are not TLS endpoints; surface the absence of
            # transport encryption directly instead of probing a fake TLS port.
            if parsed.scheme == "http":
                findings.append(Finding(
                    title="No TLS — target uses plain HTTP",
                    severity=Severity.MEDIUM,
                    finding_state=FindingState.CONFIRMED,
                    confidence_score=0.95,
                    cvss_score=5.4,
                    description="The target is using plain HTTP without TLS encryption.",
                    evidence=f"Scheme: http, Host: {host}, Port: {port}",
                    remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
                    category="ssl",
                ))
                return findings

        # Check port reachability before attempting TLS handshake
        if not self._is_tls_port_open(host, port, self.connect_timeout):
            findings.append(Finding(
                title=f"TLS port {port} is not reachable",
                severity=Severity.INFO,
                finding_state=FindingState.INFO,
                confidence_score=0.9,
                description=f"Could not connect to {host}:{port}. The port may be closed or filtered.",
                evidence=f"Host: {host}, Port: {port}, Timeout: {self.connect_timeout}s",
                category="ssl",
            ))
            return findings

        cert = None
        cipher = None
        version = None

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()

        except ssl.SSLError as e:
            reason = getattr(e, "reason", None) or "unknown"
            findings.append(Finding(
                title=f"TLS handshake failed: {reason}",
                severity=Severity.HIGH,
                finding_state=FindingState.CONFIRMED,
                confidence_score=0.95,
                cvss_score=5.9,
                description=f"TLS handshake with {host}:{port} failed. The server may not support TLS or uses incompatible settings.",
                evidence=f"Host: {host}:{port}\nError: {e}",
                remediation="Ensure the server is configured with TLS 1.2+ and valid certificates.",
                category="ssl",
            ))
            return findings
        except OSError as e:
            logger.warning(f"SSL analysis failed for {host}:{port}: {e}")
            return findings

        # Check protocol version
        if self._is_weak_protocol(version):
            findings.append(Finding(
                title=f"Weak TLS version: {version}",
                severity=Severity.HIGH,
                finding_state=FindingState.CONFIRMED,
                confidence_score=0.98,
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
                        finding_state=FindingState.CONFIRMED,
                        confidence_score=0.95,
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
                expiry = self._parse_cert_date(not_after)
                if expiry:
                    now = datetime.now(timezone.utc) if expiry.tzinfo else datetime.now()
                    days_left = (expiry - now).days
                    if days_left < 0:
                        findings.append(Finding(
                            title="SSL certificate expired",
                            severity=Severity.HIGH, cvss_score=5.9,
                            finding_state=FindingState.CONFIRMED,
                            confidence_score=0.99,
                            evidence=f"Expired: {not_after} ({abs(days_left)} days ago)",
                            remediation="Renew the SSL certificate immediately.",
                            category="ssl",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title=f"SSL certificate expires in {days_left} days",
                            severity=Severity.MEDIUM, cvss_score=3.7,
                            finding_state=FindingState.INFO,
                            confidence_score=0.99,
                            evidence=f"Expires: {not_after}",
                            remediation="Renew the certificate before expiration.",
                            category="ssl",
                        ))

            # Self-signed check
            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            if issuer == subject:
                findings.append(Finding(
                    title="Self-signed SSL certificate",
                    severity=Severity.MEDIUM, cvss_score=4.3,
                    finding_state=FindingState.CONFIRMED,
                    confidence_score=0.97,
                    evidence=f"Issuer and Subject match: {issuer.get('commonName', 'N/A')}",
                    remediation="Use a certificate from a trusted Certificate Authority.",
                    category="ssl",
                ))

        if not findings:
            findings.append(Finding(
                title=f"SSL/TLS configuration OK ({version})",
                severity=Severity.INFO,
                finding_state=FindingState.INFO,
                confidence_score=0.85,
                evidence=f"Protocol: {version}\nCipher: {cipher[0] if cipher else 'N/A'}",
                category="ssl",
            ))

        return findings
