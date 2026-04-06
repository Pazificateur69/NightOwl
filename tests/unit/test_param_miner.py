"""Tests for param miner discovery-aware behavior."""

import asyncio

import httpx

from nightowl.models.target import Target
from nightowl.modules.web.param_miner import ParamMinerPlugin


def test_run_discovers_hidden_parameter_on_linked_route():
    async def scenario():
        plugin = ParamMinerPlugin(
            {
                "discovery_depth": 1,
                "discovery_max_pages": 4,
                "discovery_max_urls": 4,
                "max_candidate_urls": 4,
                "param_wordlist": ["debug"],
                "test_values": ["1"],
            }
        )

        root_html = '<html><body><a href="/products?q=apple">products</a></body></html>'

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/" and not request.url.query:
                return httpx.Response(200, text=root_html, headers={"content-type": "text/html"})

            if request.url.path == "/products":
                if request.url.params.get("debug") == "1":
                    return httpx.Response(
                        500,
                        text="debug mode enabled with stack trace",
                        headers={"content-type": "text/html", "x-debug": "1"},
                    )
                return httpx.Response(200, text="<html>products</html>", headers={"content-type": "text/html"})

            return httpx.Response(404, text="not found")

        transport = httpx.MockTransport(handler)

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test/"))

        assert any(f.title == "Hidden parameter: debug=1" for f in findings)
        matching = next(f for f in findings if f.title == "Hidden parameter: debug=1")
        assert "Base URL: http://example.test/products?q=apple" in matching.evidence

    asyncio.run(scenario())
