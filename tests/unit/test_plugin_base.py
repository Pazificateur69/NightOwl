"""Tests for shared plugin base HTTP configuration."""

import asyncio

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.target import Target


class DummyPlugin(ScannerPlugin):
    name = "dummy-http-plugin"

    async def run(self, target: Target, **kwargs):
        return []


def test_shared_http_settings_are_loaded_from_config():
    plugin = DummyPlugin(
        config={
            "timeout": 12,
            "user_agent": "NightOwl-Test/1.0",
            "follow_redirects": False,
            "verify_ssl": True,
            "proxy": "http://127.0.0.1:8080",
            "rate_limit": {"delay_between_requests": 0.25},
        }
    )

    assert plugin.timeout == 12
    assert plugin.user_agent == "NightOwl-Test/1.0"
    assert plugin.follow_redirects is False
    assert plugin.verify_ssl is True
    assert plugin.proxy == "http://127.0.0.1:8080"
    assert plugin.request_delay == 0.25


def test_shared_request_headers_include_user_agent():
    plugin = DummyPlugin(config={"user_agent": "NightOwl-Test/1.0"})

    headers = plugin.get_request_headers({"Origin": "https://example.com"})

    assert headers["User-Agent"] == "NightOwl-Test/1.0"
    assert headers["Origin"] == "https://example.com"


def test_shared_request_headers_and_cookies_can_be_loaded_from_config():
    plugin = DummyPlugin(
        config={
            "user_agent": "NightOwl-Test/1.0",
            "headers": {"X-Benchmark": "auth-flow"},
            "cookies": {"PHPSESSID": "abc123", "security": "low"},
        }
    )

    headers = plugin.get_request_headers()

    assert headers["User-Agent"] == "NightOwl-Test/1.0"
    assert headers["X-Benchmark"] == "auth-flow"
    assert plugin.default_cookies["PHPSESSID"] == "abc123"


def test_bootstrap_auth_applies_bearer_token_and_api_key_headers():
    async def scenario():
        plugin = DummyPlugin(
            config={
                "auth": {
                    "bearer_token": "abc.def.ghi",
                    "api_key": "secret-key",
                    "api_key_header": "X-API-Key",
                    "headers": {"X-Tenant": "acme"},
                    "cookies": {"session": "cookie123"},
                }
            }
        )
        client = httpx.AsyncClient()
        await plugin.bootstrap_auth(client)
        assert client.headers["Authorization"] == "Bearer abc.def.ghi"
        assert client.headers["X-API-Key"] == "secret-key"
        assert client.headers["X-Tenant"] == "acme"
        assert client.cookies.get("session") == "cookie123"
        await client.aclose()

    asyncio.run(scenario())
