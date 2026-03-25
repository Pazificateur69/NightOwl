"""Port scanning plugin for NightOwl recon stage.

Uses python-nmap to perform TCP/UDP port scans against a target,
with configurable port ranges and scan arguments.
"""

import asyncio
import logging
from typing import Any

import nmap

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Well-known ports that often host critical services.
_TOP_100_PORTS = (
    "7,20,21,22,23,25,43,53,67,68,69,79,80,88,110,111,113,119,123,135,"
    "137,138,139,143,161,162,179,194,201,264,389,443,445,464,497,500,512,"
    "513,514,515,520,521,540,548,554,587,631,636,646,873,990,993,995,"
    "1025,1026,1027,1028,1029,1080,1194,1214,1241,1311,1433,1434,1512,"
    "1589,1701,1723,1741,1812,1813,1900,2049,2082,2083,2100,2222,2375,"
    "2376,2483,2484,3000,3128,3268,3269,3306,3389,3690,4443,4567,4848,"
    "5000,5060,5432,5900,5984,6379,6667,8000,8008,8080,8443,8888,9090,"
    "9200,9300,27017"
)


class PortScannerPlugin(ScannerPlugin):
    """Scan target ports using nmap and report open services."""

    name = "port-scanner"
    description = "TCP/UDP port scanning with service detection via python-nmap"
    version = "1.0.0"
    stage = "recon"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self._ports: str = self.config.get("ports", _TOP_100_PORTS)
        self._scan_args: str = self.config.get("scan_args", "-sV -sS -T4")
        self._top_ports: int | None = self.config.get("top_ports")
        self._timeout: int = self.config.get("timeout", 300)
        self._sudo: bool = self.config.get("sudo", False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def run(self, target: Target, **kwargs) -> list[Finding]:
        host = target.ip or target.host
        logger.info(f"[{self.name}] Starting port scan on {host}")

        try:
            scan_result = await asyncio.to_thread(self._do_scan, host)
        except Exception as exc:
            logger.error(f"[{self.name}] nmap scan failed: {exc}")
            return [
                Finding(
                    title=f"Port scan failed for {host}",
                    description=f"nmap scan could not complete: {exc}",
                    severity=Severity.INFO,
                    category="port-scan",
                    metadata={"error": str(exc)},
                )
            ]

        return self._parse_results(host, scan_result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _do_scan(self, host: str) -> nmap.PortScanner:
        """Run the nmap scan synchronously (called via to_thread)."""
        scanner = nmap.PortScanner()

        arguments = self._scan_args
        if self._top_ports:
            arguments += f" --top-ports {self._top_ports}"

        ports = None if self._top_ports else self._ports

        scanner.scan(
            hosts=host,
            ports=ports,
            arguments=arguments,
            sudo=self._sudo,
            timeout=self._timeout,
        )
        return scanner

    def _parse_results(self, host: str, scanner: nmap.PortScanner) -> list[Finding]:
        findings: list[Finding] = []
        open_ports: list[dict[str, Any]] = []

        for scanned_host in scanner.all_hosts():
            for proto in scanner[scanned_host].all_protocols():
                ports = sorted(scanner[scanned_host][proto].keys())
                for port in ports:
                    info = scanner[scanned_host][proto][port]
                    state = info.get("state", "unknown")

                    if state != "open":
                        continue

                    service_name = info.get("name", "unknown")
                    product = info.get("product", "")
                    version = info.get("version", "")
                    extra = info.get("extrainfo", "")
                    cpe = info.get("cpe", "")

                    service_str = service_name
                    if product:
                        service_str += f" ({product}"
                        if version:
                            service_str += f" {version}"
                        if extra:
                            service_str += f" - {extra}"
                        service_str += ")"

                    severity = self._rate_port_severity(port, service_name)

                    port_entry = {
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "extra": extra,
                        "cpe": cpe,
                    }
                    open_ports.append(port_entry)

                    findings.append(
                        Finding(
                            title=f"Open port {port}/{proto} ({service_str}) on {scanned_host}",
                            description=(
                                f"Port {port}/{proto} is open on {scanned_host} "
                                f"running {service_str}."
                            ),
                            severity=severity,
                            category="open-port",
                            port=port,
                            protocol=proto,
                            evidence=(
                                f"Port: {port}/{proto}\n"
                                f"State: {state}\n"
                                f"Service: {service_name}\n"
                                f"Product: {product}\n"
                                f"Version: {version}\n"
                                f"CPE: {cpe}"
                            ),
                            remediation=(
                                "Review whether this port needs to be externally accessible. "
                                "Close unused ports and restrict access with firewall rules."
                            ),
                            metadata=port_entry,
                        )
                    )

        # Summary finding
        if open_ports:
            findings.append(
                Finding(
                    title=f"Port scan summary for {host}",
                    description=(
                        f"Discovered {len(open_ports)} open port(s) on {host}."
                    ),
                    severity=Severity.INFO,
                    category="port-scan",
                    evidence="\n".join(
                        f"{p['port']}/{p['protocol']} - {p['service']} "
                        f"{p['product']} {p['version']}".strip()
                        for p in open_ports
                    ),
                    metadata={
                        "host": host,
                        "open_port_count": len(open_ports),
                        "open_ports": open_ports,
                        "scan_args": self._scan_args,
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    title=f"No open ports found on {host}",
                    description="The port scan did not discover any open ports.",
                    severity=Severity.INFO,
                    category="port-scan",
                    metadata={"host": host, "scan_args": self._scan_args},
                )
            )

        return findings

    @staticmethod
    def _rate_port_severity(port: int, service: str) -> Severity:
        """Assign severity based on the type of service discovered."""
        critical_services = {"telnet", "ftp", "rlogin", "rsh", "rexec"}
        high_services = {"mysql", "ms-sql-s", "postgresql", "oracle", "redis", "mongodb", "vnc"}
        medium_services = {"http", "https", "ssh", "smtp", "snmp", "ldap"}

        svc = service.lower()
        if svc in critical_services:
            return Severity.MEDIUM
        if svc in high_services:
            return Severity.LOW
        if svc in medium_services:
            return Severity.INFO
        return Severity.INFO
