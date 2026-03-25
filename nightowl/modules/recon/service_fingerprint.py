"""Service fingerprinting plugin for NightOwl recon stage.

Performs banner grabbing via raw sockets and HTTP server header
detection to identify services and their versions running on open ports.
"""

import asyncio
import logging
import socket
from urllib.parse import urlparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Ports commonly associated with banner-based services
_BANNER_PORTS: list[int] = [
    21, 22, 23, 25, 80, 110, 143, 443, 465, 587,
    993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9200, 11211, 27017,
]

# Probes to send to coax a response from quiet services
_SERVICE_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443: b"",  # TLS ports handled via HTTP
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"",
}


class ServiceFingerprintPlugin(ScannerPlugin):
    """Fingerprint services via banner grabbing and HTTP header detection."""

    name = "service-fingerprint"
    description = "Banner grabbing and HTTP server header detection for service identification"
    version = "1.0.0"
    stage = "recon"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self._timeout: float = self.config.get("timeout", 5.0)
        self._ports: list[int] = self.config.get("ports", list(_BANNER_PORTS))
        self._user_agent: str = self.config.get("user_agent", "NightOwl/1.0")
        self._concurrency: int = self.config.get("concurrency", 20)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def run(self, target: Target, **kwargs) -> list[Finding]:
        host = self._resolve_host(target)
        if not host:
            logger.warning(f"[{self.name}] Cannot determine host for {target.host}")
            return []

        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self._concurrency)

        async def _probe_port(port: int) -> Finding | None:
            async with semaphore:
                return await self._fingerprint_port(host, port)

        tasks = [_probe_port(port) for port in self._ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)
            elif isinstance(result, Exception):
                logger.debug(f"[{self.name}] Probe exception: {result}")

        # Also attempt HTTP-based detection if target has a URL
        http_findings = await self._detect_http_headers(target)
        findings.extend(http_findings)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _resolve_host(self, target: Target) -> str | None:
        """Extract a connectable host string from the target."""
        if target.ip:
            return target.ip
        if target.domain:
            return target.domain
        if target.url:
            parsed = urlparse(target.url)
            return parsed.hostname
        return target.host

    async def _grab_banner(self, host: str, port: int) -> str | None:
        """Connect to a port and attempt to read a service banner."""
        try:
            probe = _SERVICE_PROBES.get(port, b"")

            def _do_grab() -> str | None:
                try:
                    with socket.create_connection(
                        (host, port), timeout=self._timeout
                    ) as sock:
                        sock.settimeout(self._timeout)
                        # Some services send a banner immediately
                        if probe:
                            sock.sendall(probe)
                        data = sock.recv(1024)
                        if data:
                            return data.decode("utf-8", errors="replace").strip()
                except (
                    socket.timeout,
                    ConnectionRefusedError,
                    ConnectionResetError,
                    OSError,
                ):
                    return None
                return None

            return await asyncio.to_thread(_do_grab)

        except Exception as exc:
            logger.debug(f"[{self.name}] Banner grab failed {host}:{port}: {exc}")
            return None

    async def _fingerprint_port(self, host: str, port: int) -> Finding | None:
        """Attempt to fingerprint a single port via banner grabbing."""
        banner = await self._grab_banner(host, port)
        if not banner:
            return None

        service_name, version = self._parse_banner(banner, port)

        evidence_lines = [
            f"Host: {host}",
            f"Port: {port}",
            f"Service: {service_name}",
        ]
        if version:
            evidence_lines.append(f"Version: {version}")
        evidence_lines.append(f"Banner: {banner[:500]}")

        return Finding(
            title=f"Service identified on {host}:{port} - {service_name}",
            description=(
                f"Banner grabbing on port {port} identified the service as "
                f"{service_name}"
                + (f" version {version}" if version else "")
                + "."
            ),
            severity=Severity.INFO,
            category="service-fingerprint",
            port=port,
            evidence="\n".join(evidence_lines),
            remediation=(
                "Review whether this service needs to be publicly accessible. "
                "Ensure the service is up to date and properly configured."
            ),
            metadata={
                "host": host,
                "port": port,
                "service": service_name,
                "version": version or "",
                "banner": banner[:1000],
            },
        )

    def _parse_banner(self, banner: str, port: int) -> tuple[str, str]:
        """Extract service name and version from a banner string."""
        banner_lower = banner.lower()

        # SSH
        if banner_lower.startswith("ssh-"):
            parts = banner.split("-", 2)
            version = parts[1] if len(parts) > 1 else ""
            product = parts[2].split(" ")[0] if len(parts) > 2 else ""
            return f"SSH ({product})" if product else "SSH", version

        # FTP
        if "ftp" in banner_lower or banner.startswith("220"):
            return "FTP", self._extract_version(banner)

        # SMTP
        if "smtp" in banner_lower or "esmtp" in banner_lower:
            return "SMTP", self._extract_version(banner)

        # POP3
        if banner_lower.startswith("+ok"):
            return "POP3", self._extract_version(banner)

        # IMAP
        if "imap" in banner_lower or banner.startswith("* OK"):
            return "IMAP", self._extract_version(banner)

        # MySQL
        if "mysql" in banner_lower or port == 3306:
            return "MySQL", self._extract_version(banner)

        # PostgreSQL
        if "postgresql" in banner_lower or port == 5432:
            return "PostgreSQL", self._extract_version(banner)

        # Redis
        if "redis" in banner_lower or port == 6379:
            return "Redis", self._extract_version(banner)

        # HTTP response from banner
        if banner.startswith("HTTP/"):
            server = ""
            for line in banner.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break
            return f"HTTP ({server})" if server else "HTTP", self._extract_version(server or banner)

        # MongoDB
        if port == 27017:
            return "MongoDB", self._extract_version(banner)

        # Elasticsearch
        if port == 9200:
            return "Elasticsearch", self._extract_version(banner)

        return "Unknown", ""

    @staticmethod
    def _extract_version(text: str) -> str:
        """Try to extract a version number from text."""
        import re

        match = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[._-]\w+)?)", text)
        return match.group(1) if match else ""

    async def _detect_http_headers(self, target: Target) -> list[Finding]:
        """Detect services from HTTP response headers."""
        findings: list[Finding] = []

        urls = []
        if target.url:
            urls.append(target.url)
        else:
            host = target.domain or target.ip or target.host
            if target.port in (443, 8443):
                urls.append(f"https://{host}:{target.port}" if target.port != 443 else f"https://{host}")
            elif target.port:
                urls.append(f"http://{host}:{target.port}")
            else:
                urls.extend([f"https://{host}", f"http://{host}"])

        for url in urls:
            try:
                async with httpx.AsyncClient(
                    verify=False,
                    follow_redirects=True,
                    timeout=self._timeout,
                ) as client:
                    response = await client.head(
                        url, headers={"User-Agent": self._user_agent}
                    )

                    server = response.headers.get("server", "")
                    powered_by = response.headers.get("x-powered-by", "")

                    if server or powered_by:
                        evidence_parts = [f"URL: {url}"]
                        if server:
                            evidence_parts.append(f"Server: {server}")
                        if powered_by:
                            evidence_parts.append(f"X-Powered-By: {powered_by}")

                        tech_name = server or powered_by
                        findings.append(
                            Finding(
                                title=f"HTTP server detected: {tech_name}",
                                description=(
                                    f"HTTP headers from {url} reveal the server "
                                    f"technology in use."
                                ),
                                severity=Severity.INFO,
                                category="service-fingerprint",
                                evidence="\n".join(evidence_parts),
                                remediation=(
                                    "Consider removing or obfuscating server identification "
                                    "headers to reduce the attack surface."
                                ),
                                metadata={
                                    "url": url,
                                    "server": server,
                                    "x_powered_by": powered_by,
                                    "status_code": response.status_code,
                                },
                            )
                        )

            except httpx.RequestError as exc:
                logger.debug(f"[{self.name}] HTTP probe failed for {url}: {exc}")

        return findings
