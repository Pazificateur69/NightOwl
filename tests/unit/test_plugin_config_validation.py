"""Tests for plugin config validation and scope enforcement."""

import asyncio

import pytest

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, FindingState, Severity
from nightowl.models.target import Target


class DummyPlugin(ScannerPlugin):
    name = "dummy-plugin"
    description = "Test plugin"
    version = "1.0.0"
    stage = "scan"
    config_schema = {
        "max_items": (int, 10),
        "enabled": (bool, True),
        "label": (str, "default"),
    }

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        return []


class TestConfigValidation:
    def test_defaults_applied_for_missing_keys(self):
        plugin = DummyPlugin()
        assert plugin.config["max_items"] == 10
        assert plugin.config["enabled"] is True
        assert plugin.config["label"] == "default"

    def test_user_values_preserved(self):
        plugin = DummyPlugin(config={"max_items": 50, "label": "custom"})
        assert plugin.config["max_items"] == 50
        assert plugin.config["label"] == "custom"

    def test_wrong_type_replaced_with_default(self):
        plugin = DummyPlugin(config={"max_items": "not_a_number"})
        assert plugin.config["max_items"] == 10  # replaced with default

    def test_unknown_keys_preserved(self):
        plugin = DummyPlugin(config={"custom_key": "value"})
        assert plugin.config["custom_key"] == "value"


class LeakingPlugin(ScannerPlugin):
    name = "leaking-plugin"
    description = "Plugin that produces out-of-scope findings"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        return [
            Finding(
                title="Test finding",
                severity=Severity.LOW,
                finding_state=FindingState.INFO,
                confidence_score=0.5,
                evidence="test evidence",
                category="test",
                metadata={"url": "https://out-of-scope.evil.com/secret"},
            ),
            Finding(
                title="Normal finding",
                severity=Severity.LOW,
                finding_state=FindingState.INFO,
                confidence_score=0.5,
                evidence="test evidence",
                category="test",
                metadata={"url": "https://test.local/page"},
            ),
        ]


class TestScopeEnforcementInFindings:
    def test_out_of_scope_url_redacted_in_metadata(self):
        plugin = LeakingPlugin()
        target = Target(host="https://test.local")

        findings = asyncio.run(plugin.execute(target))
        leaked = findings[0]
        assert leaked.metadata["url"] == "[REDACTED-OUT-OF-SCOPE]"

        normal = findings[1]
        assert normal.metadata["url"] == "https://test.local/page"

    def test_findings_enriched_with_module_name(self):
        plugin = LeakingPlugin()
        target = Target(host="https://test.local")

        findings = asyncio.run(plugin.execute(target))
        for f in findings:
            assert f.module_name == "leaking-plugin"
            assert f.target == "https://test.local"
