"""Directory bruteforce scanner plugin."""

import asyncio
import logging

import httpx

from nightowl.config.defaults import COMMON_DIRS
from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class DirBruteforcePlugin(ScannerPlugin):
    name = "dir-bruteforce"
    description = "Discover hidden directories and files via bruteforce"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = (target.url or f"https://{target.host}").rstrip("/")
        wordlist = self.config.get("wordlist", COMMON_DIRS)
        delay = self.config.get("delay", 0.1)

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8) as client:
                for path in wordlist:
                    test_url = f"{base_url}/{path}"
                    try:
                        resp = await client.get(test_url)
                        if resp.status_code in (200, 301, 302, 403):
                            sev = Severity.MEDIUM if resp.status_code == 200 else Severity.INFO
                            findings.append(Finding(
                                title=f"Discovered: /{path} ({resp.status_code})",
                                severity=sev,
                                description=f"Path /{path} returned HTTP {resp.status_code}",
                                evidence=f"URL: {test_url}\nStatus: {resp.status_code}\nSize: {len(resp.content)} bytes",
                                category="dir-bruteforce",
                            ))
                    except Exception:
                        pass
                    await asyncio.sleep(delay)

        except Exception as e:
            logger.warning(f"Dir bruteforce failed: {e}")

        return findings
