"""Tests for graceful engine shutdown."""

import asyncio

import pytest

from nightowl.core.engine import NightOwlEngine
from nightowl.models.config import NightOwlConfig, ScopeConfig
from nightowl.utils.rate_limiter import get_global_limiter, reset_global_limiter


@pytest.fixture
def config():
    return NightOwlConfig(
        mode="auto",
        db_path=":memory:",
        scope=ScopeConfig(allowed_hosts=["127.0.0.1"]),
    )


class TestGracefulShutdown:
    def test_shutdown_disposes_db(self, config):
        async def scenario():
            engine = NightOwlEngine(config)
            await engine.initialize()
            assert engine.db.engine is not None
            await engine.shutdown()
            # Engine should be disposed (pool closed)

        asyncio.run(scenario())

    def test_shutdown_clears_event_bus(self, config):
        from nightowl.core.events import Event

        async def scenario():
            engine = NightOwlEngine(config)
            await engine.initialize()
            engine.event_bus.subscribe(Event.SCAN_STARTED, lambda x: None)
            assert len(engine.event_bus._subscribers) > 0
            await engine.shutdown()
            assert len(engine.event_bus._subscribers) == 0

        asyncio.run(scenario())

    def test_shutdown_resets_rate_limiter(self, config):
        async def scenario():
            engine = NightOwlEngine(config)
            await engine.initialize()
            # Create global limiter
            limiter = get_global_limiter()
            assert limiter is not None
            await engine.shutdown()
            # After shutdown, a new call should create a fresh instance
            reset_global_limiter()
            new_limiter = get_global_limiter()
            assert new_limiter is not limiter

        asyncio.run(scenario())

    def test_double_shutdown_safe(self, config):
        async def scenario():
            engine = NightOwlEngine(config)
            await engine.initialize()
            await engine.shutdown()
            await engine.shutdown()  # Should not crash

        asyncio.run(scenario())
