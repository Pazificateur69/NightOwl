"""Tests for shared web discovery helpers."""

import asyncio

import httpx

from nightowl.utils.web_discovery import discover_web_attack_surface


def test_discover_web_attack_surface_collects_query_links_and_forms():
    async def scenario():
        html = """
        <html>
          <body>
            <a href="/search?q=owl">search</a>
            <a href="/plain">plain</a>
            <form method="POST" action="/submit">
              <input type="text" name="query" />
              <input type="hidden" name="stage" value="1" />
            </form>
          </body>
        </html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, text=html, headers={"content-type": "text/html"})
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

        result = await discover_web_attack_surface(
            httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://example.test"),
            "http://example.test/",
            default_value_fn=lambda name: "1" if name == "query" else "test",
            request_headers={},
        )

        assert "http://example.test/search?q=owl" in result.urls_with_params
        assert len(result.forms) == 1
        assert result.forms[0].action_url == "http://example.test/submit"
        assert result.forms[0].attackable_params == ["query"]

    asyncio.run(scenario())
