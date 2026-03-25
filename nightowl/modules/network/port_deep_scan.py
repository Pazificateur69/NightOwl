"""Deep port scanner with service/version detection using python-nmap."""

import asyncio
import logging

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class DeepPortScanPlugin(ScannerPlugin):
    """Performs deep port scanning with service version detection and NSE scripts."""

    name = "deep-port-scan"
    description = "Deep port scan with service version and NSE script detection (-sV -sC)"
    stage = "scan"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.port_range: str = self.config.get("port_range", "1-65535")
        self.scan_arguments: str = self.config.get("scan_arguments", "-sV -sC -T4")
        self.timeout: int = self.config.get("timeout", 600)

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []

        try:
            import nmap
        except ImportError:
            logger.error("[deep-port-scan] python-nmap not installed. pip install python-nmap")
            return [
                Finding(
                    title="Deep Port Scan Unavailable",
                    description="python-nmap library is not installed.",
                    severity=Severity.INFO,
                    category="configuration",
                )
            ]

        try:
            scanner = nmap.PortScanner()
            host = target.ip or target.host

            logger.info(f"[deep-port-scan] Scanning {host} ports {self.port_range}")

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: scanner.scan(
                    host,
                    self.port_range,
                    arguments=self.scan_arguments,
                    timeout=self.timeout,
                ),
            )

            for scanned_host in scanner.all_hosts():
                for proto in scanner[scanned_host].all_protocols():
                    ports = sorted(scanner[scanned_host][proto].keys())

                    for port in ports:
                        port_info = scanner[scanned_host][proto][port]
                        state = port_info.get("state", "unknown")

                        if state != "open":
                            continue

                        service_name = port_info.get("name", "unknown")
                        product = port_info.get("product", "")
                        version = port_info.get("version", "")
                        extra_info = port_info.get("extrainfo", "")
                        cpe = port_info.get("cpe", "")

                        service_str = service_name
                        if product:
                            service_str += f" ({product}"
                            if version:
                                service_str += f" {version}"
                            service_str += ")"

                        # Determine severity based on service type
                        severity = Severity.INFO
                        risky_services = {
                            "telnet", "ftp", "rsh", "rlogin", "rexec",
                            "vnc", "rdp", "mysql", "mssql", "postgresql",
                            "mongodb", "redis", "memcached", "elasticsearch",
                        }
                        if service_name.lower() in risky_services:
                            severity = Severity.MEDIUM

                        # Check for script output (NSE results)
                        script_output = port_info.get("script", {})
                        nse_details = ""
                        if script_output:
                            nse_lines = []
                            for script_name, output in script_output.items():
                                nse_lines.append(f"  {script_name}: {output}")
                                # Elevate severity if scripts found vulns
                                lower_output = output.lower()
                                if any(
                                    w in lower_output
                                    for w in ["vulnerable", "exploit", "cve-", "critical"]
                                ):
                                    severity = Severity.HIGH
                            nse_details = "\n".join(nse_lines)

                        description = (
                            f"Port {port}/{proto} is open running {service_str}.\n"
                            f"State: {state}"
                        )
                        if extra_info:
                            description += f"\nExtra info: {extra_info}"
                        if nse_details:
                            description += f"\n\nNSE Script Results:\n{nse_details}"

                        findings.append(
                            Finding(
                                title=f"Open Port {port}/{proto} - {service_str}",
                                description=description,
                                severity=severity,
                                category="network",
                                port=port,
                                protocol=proto,
                                evidence=f"nmap {self.scan_arguments} -p {port} {host}",
                                metadata={
                                    "service": service_name,
                                    "product": product,
                                    "version": version,
                                    "extra_info": extra_info,
                                    "cpe": cpe,
                                    "state": state,
                                    "scripts": script_output,
                                    "port": port,
                                    "protocol": proto,
                                },
                                remediation=(
                                    f"Review whether port {port} ({service_name}) needs "
                                    f"to be exposed. Close unused ports and update "
                                    f"services to latest versions."
                                ),
                            )
                        )

            if not findings:
                findings.append(
                    Finding(
                        title=f"No open ports found on {host}",
                        description=f"Deep port scan of {host} found no open ports in range {self.port_range}.",
                        severity=Severity.INFO,
                        category="network",
                    )
                )

        except nmap.PortScannerError as e:
            logger.error(f"[deep-port-scan] Nmap error: {e}")
            findings.append(
                Finding(
                    title="Deep Port Scan Error",
                    description=f"Nmap scan failed: {e}. Ensure nmap is installed on the system.",
                    severity=Severity.INFO,
                    category="error",
                )
            )
        except Exception as e:
            logger.error(f"[deep-port-scan] Unexpected error: {e}")
            findings.append(
                Finding(
                    title="Deep Port Scan Error",
                    description=f"Unexpected error during scan: {e}",
                    severity=Severity.INFO,
                    category="error",
                )
            )

        return findings
