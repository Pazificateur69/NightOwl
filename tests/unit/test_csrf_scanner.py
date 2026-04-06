"""Tests for CSRF scanner discovery-aware behavior."""

import asyncio

import httpx

from nightowl.models.target import Target
from nightowl.modules.web.csrf_scanner import CSRFScannerPlugin


def test_run_discovers_post_form_from_entry_page():
    async def scenario():
        plugin = CSRFScannerPlugin(
            {
                "discovery_depth": 1,
                "discovery_max_pages": 4,
                "discovery_max_forms": 4,
            }
        )

        root_html = """
        <html>
          <body>
            <a href="/account">account</a>
          </body>
        </html>
        """
        account_html = """
        <html>
          <body>
            <form method="POST" action="/account/update">
              <input type="text" name="email" />
            </form>
          </body>
        </html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/" and not request.url.query:
                return httpx.Response(200, text=root_html, headers={"content-type": "text/html"})
            if request.url.path == "/account":
                return httpx.Response(200, text=account_html, headers={"content-type": "text/html"})
            return httpx.Response(404, text="not found")

        transport = httpx.MockTransport(handler)

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test/"))

        assert len(findings) == 1
        assert findings[0].title == "Form without CSRF protection: /account/update"

    asyncio.run(scenario())
