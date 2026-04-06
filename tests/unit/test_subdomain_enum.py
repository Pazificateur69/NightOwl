"""Tests for subdomain enumeration safety and limiter behavior."""

import asyncio

from nightowl.models.target import Target
from nightowl.modules.recon import subdomain as subdomain_module
from nightowl.modules.recon.subdomain import SubdomainPlugin


class _FakeLimiter:
    acquire_calls = 0
    release_calls = 0

    def __init__(self, rate=0.0, burst=0):
        pass

    async def acquire(self):
        type(self).acquire_calls += 1

    def release(self):
        type(self).release_calls += 1


def test_subdomain_plugin_releases_limiter_for_each_candidate(monkeypatch):
    async def scenario():
        monkeypatch.setattr(subdomain_module, "RateLimiter", _FakeLimiter)
        plugin = SubdomainPlugin(config={"wordlist": "", "concurrency": 2})
        monkeypatch.setattr(plugin, "_load_wordlist", lambda: ["www", "api", "mail"])
        async def fake_resolve(_fqdn):
            return None
        monkeypatch.setattr(plugin, "_resolve", fake_resolve)

        findings = await plugin.run(Target(host="example.com"))
        assert len(findings) == 1
        assert _FakeLimiter.acquire_calls == 3
        assert _FakeLimiter.release_calls == 3

    asyncio.run(scenario())
