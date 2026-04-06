"""Focused tests for SQLi scanner form handling."""

import asyncio

import httpx

from nightowl.models.target import Target
from nightowl.modules.web.sqli_scanner import SQLiScannerPlugin


def test_extract_form_targets_keeps_action_and_attackable_fields():
    plugin = SQLiScannerPlugin()
    html = """
    <html>
      <body>
        <form method="POST" action="/SqlInjection/attack2">
          <input type="text" name="query" value="" />
          <input type="hidden" name="stage" value="lesson2" />
          <input type="submit" name="submit" value="Go" />
        </form>
      </body>
    </html>
    """
    targets = plugin._extract_form_targets(html, "http://example.test/WebGoat/SqlInjection.lesson")
    assert len(targets) == 1
    assert targets[0]["method"] == "post"
    assert targets[0]["url"] == "http://example.test/SqlInjection/attack2"
    assert targets[0]["params"]["query"] == "1"
    assert targets[0]["params"]["stage"] == "lesson2"
    assert targets[0]["attackable_params"] == ["query"]


def test_run_detects_error_based_sqli_from_post_form():
    async def scenario():
        plugin = SQLiScannerPlugin()

        lesson_html = """
        <html>
          <body>
            <form method="POST" action="/SqlInjection/attack2">
              <input type="text" name="query" value="" />
            </form>
          </body>
        </html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/SqlInjection.lesson":
                return httpx.Response(200, text=lesson_html, headers={"content-type": "text/html"})

            if request.method == "POST" and request.url.path == "/SqlInjection/attack2":
                body = request.content.decode()
                if "query=%27" in body:
                    return httpx.Response(
                        200,
                        text="{\"output\":\"malformed string: '\"}",
                        headers={"content-type": "application/json"},
                    )
                return httpx.Response(
                    200,
                    text='{"output":"ok"}',
                    headers={"content-type": "application/json"},
                )

            return httpx.Response(404, text="not found")

        transport = httpx.MockTransport(handler)

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test/SqlInjection.lesson"))
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "SQL Injection (Error-Based) in 'query'"
        assert finding.metadata["request_method"] == "POST"
        assert finding.metadata["action_url"] == "http://example.test/SqlInjection/attack2"

    asyncio.run(scenario())


def test_run_discovers_query_route_from_entry_page():
    async def scenario():
        plugin = SQLiScannerPlugin(
            {
                "discovery_depth": 1,
                "discovery_max_pages": 4,
                "discovery_max_urls": 4,
                "discovery_max_forms": 2,
            }
        )

        root_html = '<html><body><a href="/products?q=apple">products</a></body></html>'

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/" and not request.url.query:
                return httpx.Response(200, text=root_html, headers={"content-type": "text/html"})

            if request.method == "GET" and request.url.path == "/products":
                if request.url.params.get("q") == "'":
                    return httpx.Response(
                        200,
                        text="you have an error in your sql syntax",
                        headers={"content-type": "text/html"},
                    )
                return httpx.Response(
                    200,
                    text="<html><body>ok</body></html>",
                    headers={"content-type": "text/html"},
                )

            return httpx.Response(404, text="not found")

        transport = httpx.MockTransport(handler)

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test/"))

        assert len(findings) == 1
        assert findings[0].title == "SQL Injection (Error-Based) in 'q'"
        assert findings[0].metadata["technique"] == "error-based"

    asyncio.run(scenario())
