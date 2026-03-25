"""Abstract base class for all NightOwl scanner plugins."""

import logging
import time
from abc import ABC, abstractmethod

from nightowl.models.finding import Finding
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class ScannerPlugin(ABC):
    """Base class that all scanner modules must implement."""

    name: str = "base-plugin"
    description: str = ""
    author: str = "NightOwl"
    version: str = "1.0.0"
    stage: str = "scan"  # recon, scan, exploit, post

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.findings: list[Finding] = []
        self._is_setup = False

    async def setup(self) -> None:
        """Optional setup before scanning. Override if needed."""
        pass

    @abstractmethod
    async def run(self, target: Target, **kwargs) -> list[Finding]:
        """Execute the scan against a target. Must be implemented."""
        ...

    async def teardown(self) -> None:
        """Optional cleanup after scanning. Override if needed."""
        pass

    async def execute(self, target: Target, **kwargs) -> list[Finding]:
        """Full lifecycle: setup -> run -> teardown with error handling."""
        start = time.time()
        try:
            if not self._is_setup:
                await self.setup()
                self._is_setup = True

            logger.info(f"[{self.name}] Scanning {target.host}...")
            findings = await self.run(target, **kwargs)

            for f in findings:
                f.module_name = self.name
                f.target = target.host

            self.findings.extend(findings)
            elapsed = time.time() - start
            logger.info(f"[{self.name}] Found {len(findings)} findings in {elapsed:.1f}s")
            return findings

        except Exception as e:
            elapsed = time.time() - start
            logger.error(f"[{self.name}] Error after {elapsed:.1f}s: {e}")
            return []

        finally:
            try:
                await self.teardown()
            except Exception as e:
                logger.warning(f"[{self.name}] Teardown error: {e}")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} stage={self.stage}>"
