"""Network mapping / host discovery plugin."""

import asyncio
import logging
import socket
import subprocess

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class NetworkMapPlugin(ScannerPlugin):
    name = "network-map"
    description = "Discover live hosts on a network via ping sweep"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.host

        # If it's a single host, just check if alive
        if "/" not in host:
            alive = await self._ping(host)
            if alive:
                findings.append(Finding(
                    title=f"Host alive: {host}",
                    severity=Severity.INFO,
                    evidence=f"Host {host} responds to ping",
                    category="network-map",
                ))
            return findings

        # Subnet sweep
        try:
            import ipaddress
            network = ipaddress.ip_network(host, strict=False)
            hosts = list(network.hosts())[:256]  # limit to /24

            live_hosts = []
            tasks = [self._ping(str(ip)) for ip in hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for ip, alive in zip(hosts, results):
                if alive is True:
                    live_hosts.append(str(ip))

            if live_hosts:
                findings.append(Finding(
                    title=f"Discovered {len(live_hosts)} live hosts in {host}",
                    severity=Severity.INFO,
                    evidence="\n".join(live_hosts),
                    category="network-map",
                    metadata={"live_hosts": live_hosts},
                ))

        except Exception as e:
            logger.warning(f"Network map failed: {e}")

        return findings

    async def _ping(self, host: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", host,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=3)
            return proc.returncode == 0
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            return False
