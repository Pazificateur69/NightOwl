"""Tests for the NightOwl engine."""

import asyncio

import pytest

from nightowl.core.engine import NightOwlEngine
from nightowl.models.config import ModuleConfig, NightOwlConfig, ScopeConfig
from nightowl.models.target import Target


@pytest.fixture
def config():
    return NightOwlConfig(
        mode="auto",
        db_path=":memory:",
        scope=ScopeConfig(allowed_hosts=["127.0.0.1"]),
    )


class TestEngine:
    def test_scope_enforcement(self, config):
        """Targets outside scope should be rejected."""
        engine = NightOwlEngine(config)
        asyncio.run(engine.initialize())

        t = Target(host="evil.example.com")
        with pytest.raises(ValueError, match="outside the configured scope"):
            asyncio.run(engine.run_scan([t], mode="auto"))

    def test_allowed_target(self, config):
        """Targets in scope should be accepted (empty pipeline completes)."""
        engine = NightOwlEngine(config)
        asyncio.run(engine.initialize())

        t = Target(host="127.0.0.1")
        # Pass an empty module list — no plugins run, but scan completes
        session = asyncio.run(engine.run_scan([t], mode="auto", modules=[]))
        assert session.status.value == "completed"
        assert session.findings_count == 0
        assert session.errors == []
        assert session.module_status == []

    def test_session_id_reuse(self, config):
        """When session_id is passed, the engine should use it."""
        engine = NightOwlEngine(config)
        asyncio.run(engine.initialize())

        t = Target(host="127.0.0.1")
        session = asyncio.run(
            engine.run_scan([t], mode="auto", modules=[], session_id="custom-123")
        )
        assert session.id == "custom-123"

    def test_list_plugins(self, config):
        """list_plugins should return a list of dicts."""
        engine = NightOwlEngine(config)
        asyncio.run(engine.initialize())
        plugins = engine.list_plugins()
        assert isinstance(plugins, list)

    def test_url_target_matches_domain_scope(self):
        """URL targets should be checked against their effective hostname."""
        config = NightOwlConfig(
            mode="auto",
            db_path=":memory:",
            scope=ScopeConfig(allowed_hosts=["*.example.com"]),
        )
        engine = NightOwlEngine(config)
        asyncio.run(engine.initialize())

        t = Target(host="https://app.example.com/login")
        session = asyncio.run(engine.run_scan([t], mode="auto", modules=[]))
        assert session.status.value == "completed"

    def test_network_target_matches_allowed_network_scope(self):
        config = NightOwlConfig(
            mode="auto",
            db_path=":memory:",
            scope=ScopeConfig(allowed_networks=["192.168.0.0/16"]),
        )
        engine = NightOwlEngine(config)
        asyncio.run(engine.initialize())

        t = Target(host="192.168.1.0/24")
        session = asyncio.run(engine.run_scan([t], mode="auto", modules=[]))
        assert session.status.value == "completed"

    def test_pipeline_receives_module_specific_options(self):
        """run_scan should pass merged per-module options to plugins."""
        config = NightOwlConfig(
            mode="auto",
            db_path=":memory:",
            scope=ScopeConfig(allowed_hosts=["127.0.0.1"]),
            modules=[
                ModuleConfig(
                    name="deep-port-scan",
                    enabled=True,
                    options={"port_range": "1-1000"},
                )
            ],
        )
        engine = NightOwlEngine(config)
        plugin_configs = engine._build_plugin_configs(["deep-port-scan"])
        assert plugin_configs["deep-port-scan"]["port_range"] == "1-1000"
        assert plugin_configs["deep-port-scan"]["timeout"] == config.timeout
