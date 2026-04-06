"""Tests for the scan pipeline."""

import asyncio

import pytest

from nightowl.core.pipeline import ScanPipeline, Stage, STAGE_ORDER
from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.scan import ScanMode
from nightowl.models.target import Target


class DummyReconPlugin(ScannerPlugin):
    name = "dummy-recon"
    description = "Test recon"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        return [Finding(title="Recon finding", severity=Severity.INFO)]


class DummyScanPlugin(ScannerPlugin):
    name = "dummy-scan"
    description = "Test scan"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        return [Finding(title="Scan finding", severity=Severity.HIGH)]


class DummyExploitPlugin(ScannerPlugin):
    name = "dummy-exploit"
    description = "Test exploit"
    stage = "exploit"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        # Verify it receives prior findings
        prior = kwargs.get("findings", [])
        if prior:
            return [Finding(
                title=f"Exploit based on {len(prior)} prior findings",
                severity=Severity.CRITICAL,
            )]
        return []


class FailingPlugin(ScannerPlugin):
    name = "failing-plugin"
    description = "Always fails"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        raise RuntimeError("Intentional failure")


class IntraStagePlugin(ScannerPlugin):
    """Plugin that checks if it can see findings from earlier plugins in the same stage."""
    name = "intra-stage-checker"
    description = "Check intra-stage visibility"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        prior = kwargs.get("findings", [])
        return [Finding(
            title=f"Saw {len(prior)} prior findings",
            severity=Severity.INFO,
        )]


@pytest.fixture
def target():
    return Target(host="127.0.0.1")


class TestScanPipeline:
    def test_basic_pipeline(self, target):
        plugins = {
            "dummy-recon": DummyReconPlugin,
            "dummy-scan": DummyScanPlugin,
        }
        pipeline = ScanPipeline(plugins=plugins, mode=ScanMode.AUTO)
        findings = asyncio.run(pipeline.execute([target], stages=[Stage.RECON, Stage.SCAN]))
        assert len(findings) == 2
        assert findings[0].title == "Recon finding"
        assert findings[1].title == "Scan finding"

    def test_stage_filtering(self, target):
        """Only plugins matching the requested stage should run."""
        plugins = {
            "dummy-recon": DummyReconPlugin,
            "dummy-scan": DummyScanPlugin,
        }
        pipeline = ScanPipeline(plugins=plugins, mode=ScanMode.AUTO)
        findings = asyncio.run(pipeline.execute([target], stages=[Stage.SCAN]))
        assert len(findings) == 1
        assert findings[0].title == "Scan finding"

    def test_findings_propagation_to_exploit(self, target):
        """Exploit stage should receive findings from prior stages."""
        plugins = {
            "dummy-recon": DummyReconPlugin,
            "dummy-scan": DummyScanPlugin,
            "dummy-exploit": DummyExploitPlugin,
        }
        pipeline = ScanPipeline(plugins=plugins, mode=ScanMode.AUTO)
        findings = asyncio.run(pipeline.execute(
            [target],
            stages=[Stage.RECON, Stage.SCAN, Stage.EXPLOIT],
        ))
        assert len(findings) == 3
        assert "2 prior findings" in findings[2].title

    def test_intra_stage_finding_visibility(self, target):
        """Plugins in the same stage should see findings from earlier plugins."""
        plugins = {
            "dummy-scan": DummyScanPlugin,
            "intra-stage-checker": IntraStagePlugin,
        }
        pipeline = ScanPipeline(plugins=plugins, mode=ScanMode.AUTO)
        findings = asyncio.run(pipeline.execute([target], stages=[Stage.SCAN]))
        # The checker should see at least the 1 finding from dummy-scan
        checker_finding = [f for f in findings if "Saw" in f.title][0]
        assert "1 prior findings" in checker_finding.title

    def test_error_tracking(self, target):
        """Failing plugins should be tracked in pipeline errors."""
        plugins = {
            "failing-plugin": FailingPlugin,
            "dummy-scan": DummyScanPlugin,
        }
        pipeline = ScanPipeline(plugins=plugins, mode=ScanMode.AUTO)
        findings = asyncio.run(pipeline.execute([target], stages=[Stage.SCAN]))
        # dummy-scan should still produce its finding
        assert len(findings) >= 1
        # The error should be tracked
        assert len(pipeline.errors) == 1
        assert pipeline.errors[0]["module"] == "failing-plugin"
        assert "Intentional failure" in pipeline.errors[0]["error"]

    def test_cancel(self, target):
        plugins = {"dummy-recon": DummyReconPlugin, "dummy-scan": DummyScanPlugin}
        pipeline = ScanPipeline(plugins=plugins, mode=ScanMode.AUTO)
        pipeline.cancel()
        findings = asyncio.run(pipeline.execute([target]))
        assert len(findings) == 0

    def test_progress_reporting(self, target):
        plugins = {"dummy-recon": DummyReconPlugin}
        pipeline = ScanPipeline(plugins=plugins, mode=ScanMode.AUTO)
        asyncio.run(pipeline.execute([target], stages=[Stage.RECON]))
        p = pipeline.progress
        assert p["completed_stages"] >= 1
        assert p["total_findings"] >= 1
