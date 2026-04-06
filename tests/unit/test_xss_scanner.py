"""Tests for XSS scanner context analysis."""

import asyncio

import httpx

from nightowl.models.finding import FindingState
from nightowl.models.target import Target
from nightowl.modules.web.xss_scanner import XSSScannerPlugin
from nightowl.modules.web.xss_scanner import (
    _confidence_for_payload,
    _find_reflected_payload,
    _is_dangerous_context,
    _json_output_renders_html,
    _response_looks_like_html,
)


class TestXSSContextAnalysis:
    def test_html_body_reflection(self):
        """Unescaped reflection in HTML body is dangerous."""
        body = '<html><body><p><script>alert("n1GhT0wL")</script></p></body></html>'
        payload = '<script>alert("n1GhT0wL")</script>'
        assert _is_dangerous_context(payload, body) is True

    def test_entity_encoded(self):
        """Entity-encoded reflection is safe."""
        body = '<html><body>&lt;script&gt;alert("n1GhT0wL")&lt;/script&gt;</body></html>'
        payload = '<script>alert("n1GhT0wL")</script>'
        assert _is_dangerous_context(payload, body) is False

    def test_json_response(self):
        """Reflection in a JSON response is not exploitable."""
        body = '{"query": "<script>alert(\\"n1GhT0wL\\")</script>"}'
        payload = '<script>alert("n1GhT0wL")</script>'
        assert _is_dangerous_context(payload, body) is False

    def test_json_output_rendering_detection_is_specific(self):
        body = (
            '{'
            '"output":"Thank you <br \\/> Card:<script>alert(\\"n1GhT0wL\\")<\\/script>",'
            '"lessonCompleted":true'
            '}'
        )
        payload = '<script>alert("n1GhT0wL")</script>'
        reflected = _find_reflected_payload(payload, body)
        assert reflected is not None
        assert _json_output_renders_html(reflected, body) is True

    def test_plain_json_reflection_stays_non_exploitable(self):
        body = '{"query": "<script>alert(\\"n1GhT0wL\\")<\\/script>"}'
        payload = '<script>alert("n1GhT0wL")</script>'
        reflected = _find_reflected_payload(payload, body)
        assert reflected is not None
        assert _json_output_renders_html(reflected, body) is False

    def test_webgoat_double_escaped_json_output_still_matches_payload(self):
        body = (
            "{"
            '"output":"Thank you <br \\/> Card:<script>alert(\\\\\\"n1GhT0wL\\\\\\")<\\\\/script><br \\/>",'
            '"lessonCompleted":true'
            "}"
        )
        payload = '<script>alert("n1GhT0wL")</script>'
        reflected = _find_reflected_payload(payload, body)
        assert reflected is not None
        assert _json_output_renders_html(reflected, body) is True

    def test_html_comment(self):
        """Reflection inside an HTML comment is safe."""
        body = '<html><!-- <script>alert("n1GhT0wL")</script> --><body></body></html>'
        payload = '<script>alert("n1GhT0wL")</script>'
        assert _is_dangerous_context(payload, body) is False

    def test_payload_not_found(self):
        """If the payload isn't in the body, returns False."""
        body = "<html><body>Nothing here</body></html>"
        payload = '<script>alert("n1GhT0wL")</script>'
        assert _is_dangerous_context(payload, body) is False

    def test_html_detection_works_without_content_type(self):
        assert _response_looks_like_html("", "<!DOCTYPE html><html></html>") is True
        assert _response_looks_like_html("text/plain", "hello") is False

    def test_script_payload_gets_confirmed_confidence(self):
        state, confidence = _confidence_for_payload(
            '<script>alert("n1GhT0wL")</script>',
            "<html><script>alert(1)</script></html>",
            "name",
        )
        assert state == FindingState.CONFIRMED
        assert confidence >= 0.95

    def test_search_parameter_reflection_is_suspected(self):
        state, confidence = _confidence_for_payload(
            '<img src=x alt="n1GhT0wL">',
            '<html><img src=x alt="n1GhT0wL"></html>',
            "search",
        )
        assert state == FindingState.SUSPECTED
        assert confidence < 0.85

    def test_json_rendered_output_becomes_suspected_with_capped_confidence(self):
        async def scenario():
            plugin = XSSScannerPlugin()

            def handler(request: httpx.Request) -> httpx.Response:
                if request.url.params.get("field1") == "test":
                    return httpx.Response(
                        200,
                        headers={"content-type": "application/json"},
                        text='{"output":"baseline"}',
                    )
                return httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    text=(
                        "{"
                        '"output":"Thank you <br \\/> Card:<script>alert(\\\\\\"n1GhT0wL\\\\\\")<\\\\/script><br \\/>",'
                        '"lessonCompleted":true'
                        "}"
                    ),
                )

            transport = httpx.MockTransport(handler)

            def fake_client(**_kwargs):
                return httpx.AsyncClient(transport=transport)

            plugin.create_http_client = fake_client  # type: ignore[method-assign]
            target = Target(
                host="http://example.test/CrossSiteScripting/attack5a?QTY1=1&QTY2=1&QTY3=1&QTY4=1&field1=test&field2=111"
            )
            findings = await plugin.run(target)
            assert len(findings) == 1
            assert findings[0].finding_state == FindingState.SUSPECTED
            assert findings[0].confidence_score == 0.78

        asyncio.run(scenario())

    def test_run_discovers_query_route_from_entry_page(self):
        async def scenario():
            plugin = XSSScannerPlugin(
                {
                    "discovery_depth": 1,
                    "discovery_max_pages": 4,
                    "discovery_max_urls": 4,
                    "discovery_max_forms": 2,
                }
            )

            root_html = '<html><body><a href="/search?q=hello">search</a></body></html>'

            def handler(request: httpx.Request) -> httpx.Response:
                if request.url.path == "/" and not request.url.query:
                    return httpx.Response(
                        200,
                        text=root_html,
                        headers={"content-type": "text/html"},
                    )
                if request.url.path == "/search":
                    q = request.url.params.get("q", "")
                    return httpx.Response(
                        200,
                        text=f"<html><body>{q}</body></html>",
                        headers={"content-type": "text/html"},
                    )
                return httpx.Response(404, text="not found")

            transport = httpx.MockTransport(handler)

            def fake_client(**_kwargs):
                return httpx.AsyncClient(transport=transport, base_url="http://example.test")

            plugin.create_http_client = fake_client  # type: ignore[method-assign]
            findings = await plugin.run(Target(host="http://example.test/"))

            assert len(findings) == 1
            assert findings[0].title == "Reflected XSS in parameter 'q'"
            assert findings[0].metadata["method"] == "GET"

        asyncio.run(scenario())

    def test_run_uses_configured_login_bootstrap_before_scanning(self):
        async def scenario():
            plugin = XSSScannerPlugin(
                {
                    "auth": {
                        "login_url": "http://example.test/login",
                        "username": "alice",
                        "password": "secret",
                    }
                }
            )

            login_html = """
            <html><body>
              <form method="post" action="/login">
                <input type="text" name="username" />
                <input type="password" name="password" />
              </form>
            </body></html>
            """
            authenticated = {"value": False}

            def handler(request: httpx.Request) -> httpx.Response:
                if request.method == "GET" and request.url.path == "/login":
                    return httpx.Response(200, text=login_html, headers={"content-type": "text/html"})
                if request.method == "POST" and request.url.path == "/login":
                    authenticated["value"] = True
                    response = httpx.Response(302, headers={"location": "/app"})
                    response.cookies.set("session", "abc123")
                    return response
                if request.method == "GET" and request.url.path == "/" and authenticated["value"]:
                    return httpx.Response(
                        200,
                        text='<html><body><a href="/search?q=hello">search</a></body></html>',
                        headers={"content-type": "text/html"},
                    )
                if request.method == "GET" and request.url.path == "/search" and authenticated["value"]:
                    q = request.url.params.get("q", "")
                    return httpx.Response(
                        200,
                        text=f"<html><body>{q}</body></html>",
                        headers={"content-type": "text/html"},
                    )
                return httpx.Response(403, text="forbidden")

            transport = httpx.MockTransport(handler)

            def fake_client(**_kwargs):
                return httpx.AsyncClient(transport=transport, base_url="http://example.test")

            plugin.create_http_client = fake_client  # type: ignore[method-assign]
            findings = await plugin.run(Target(host="http://example.test/"))

            assert len(findings) == 1
            assert findings[0].title == "Reflected XSS in parameter 'q'"

        asyncio.run(scenario())
