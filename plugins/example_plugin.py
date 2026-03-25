"""Example custom NightOwl plugin.

Copy this file and modify to create your own scanner module.
Place custom plugins in the plugins/ directory - they will be auto-discovered.
"""

import logging

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class ExamplePlugin(ScannerPlugin):
    name = "example-plugin"
    description = "Example custom scanner plugin"
    version = "1.0.0"
    stage = "scan"  # recon | scan | exploit | post

    async def setup(self) -> None:
        """Optional: initialize resources before scanning."""
        logger.info(f"[{self.name}] Setting up...")

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        """Main scan logic. Must return a list of Finding objects."""
        findings = []

        # Your scanning logic here
        logger.info(f"[{self.name}] Scanning {target.host}...")

        # Example finding
        findings.append(Finding(
            title="Example finding from custom plugin",
            severity=Severity.INFO,
            description="This is a demo finding from the example plugin",
            evidence=f"Target: {target.host}",
            remediation="No action needed - this is a demo",
            category="example",
        ))

        return findings

    async def teardown(self) -> None:
        """Optional: clean up resources after scanning."""
        logger.info(f"[{self.name}] Teardown complete")
