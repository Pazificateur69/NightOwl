"""WHOIS lookup plugin."""

import logging
import socket

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class WhoisPlugin(ScannerPlugin):
    name = "whois-lookup"
    description = "WHOIS domain registration lookup"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        domain = target.domain or target.host

        try:
            whois_data = self._query_whois(domain)
            if whois_data:
                findings.append(Finding(
                    title=f"WHOIS data for {domain}",
                    severity=Severity.INFO,
                    description="Domain registration information retrieved",
                    evidence=whois_data[:2000],
                    category="recon",
                ))
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")

        return findings

    def _query_whois(self, domain: str, server: str = "whois.iana.org") -> str:
        try:
            sock = socket.create_connection((server, 43), timeout=10)
            sock.sendall(f"{domain}\r\n".encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            text = response.decode("utf-8", errors="ignore")

            # Follow referral
            for line in text.splitlines():
                if line.lower().startswith("refer:"):
                    referral = line.split(":", 1)[1].strip()
                    if referral and referral != server:
                        return self._query_whois(domain, referral)

            return text
        except Exception as e:
            logger.debug(f"WHOIS query to {server} failed: {e}")
            return ""
