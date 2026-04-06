"""Tests for SSTI scanner discovery-aware behavior."""

import asyncio

import httpx

from nightowl.models.target import Target
from nightowl.modules.web.ssti_scanner import SSTIPlugin


def test_run_discovers_query_route_from_entry_page():
    async def scenario():
        plugin = SSTIPlugin(
            {
                "discovery_depth": 1,
                "discovery_max_pages": 4,
                "discovery_max_urls": 4,
                "discovery_max_forms": 2,
            }
        )

        root_html = '<html><body><a href="/preview?name=test">preview</a></body></html>'

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/" and not request.url.query:
                return httpx.Response(200, text=root_html, headers={"content-type": "text/html"})
            if request.url.path == "/preview":
                name = request.url.params.get("name", "")
                if name == "{{7*7}}":
                    return httpx.Response(200, text="<html>49</html>", headers={"content-type": "text/html"})
                return httpx.Response(200, text="<html>preview</html>", headers={"content-type": "text/html"})
            return httpx.Response(404, text="not found")

        transport = httpx.MockTransport(handler)

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test/"))

        assert len(findings) == 1
        assert findings[0].title == "Server-Side Template Injection in 'name' (Jinja2/Twig)"

    asyncio.run(scenario())
