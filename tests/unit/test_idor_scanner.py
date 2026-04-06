"""Tests for IDOR scanner discovery-aware behavior."""

import asyncio

import httpx

from nightowl.models.target import Target
from nightowl.modules.web.idor_scanner import IDORScannerPlugin


def test_run_discovers_numeric_resource_link_from_entry_page():
    async def scenario():
        plugin = IDORScannerPlugin(
            {
                "discovery_depth": 1,
                "discovery_max_pages": 4,
                "discovery_max_urls": 4,
            }
        )

        root_html = '<html><body><a href="/users/123">user</a></body></html>'

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, text=root_html, headers={"content-type": "text/html"})
            if request.url.path == "/users/123":
                return httpx.Response(200, text=("A" * 150), headers={"content-type": "text/html"})
            if request.url.path == "/users/124":
                return httpx.Response(200, text=("B" * 150), headers={"content-type": "text/html"})
            return httpx.Response(404, text="not found")

        transport = httpx.MockTransport(handler)

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test/"))

        assert len(findings) == 1
        assert findings[0].title == "Potential IDOR via user ID"

    asyncio.run(scenario())
