"""Tests for auth tester shared login behavior."""

import asyncio

import httpx

from nightowl.models.target import Target
from nightowl.modules.web.auth_tester import AuthTesterPlugin


def test_auth_tester_uses_login_form_and_detects_success():
    async def scenario():
        plugin = AuthTesterPlugin(config={"delay": 0})

        login_html = """
        <html><body>
          <form method="post" action="/login">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="csrf_token" value="abc123" />
          </form>
        </body></html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/login":
                return httpx.Response(200, text=login_html, headers={"content-type": "text/html"})
            if request.method == "POST" and request.url.path == "/login":
                body = request.content.decode()
                if "username=admin" in body and "password=admin" in body and "csrf_token=abc123" in body:
                    return httpx.Response(302, headers={"location": "/dashboard"})
                return httpx.Response(200, text="invalid credentials")
            return httpx.Response(404, text="not found")

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test"))

        assert len(findings) == 1
        assert findings[0].title == "Default credentials work: admin:admin"

    asyncio.run(scenario())


def test_auth_tester_respects_configured_field_names_and_success_markers():
    async def scenario():
        plugin = AuthTesterPlugin(
            config={
                "delay": 0,
                "auth": {
                    "username_field": "emailAddress",
                    "password_field": "passwd",
                    "extra_form_fields": {"tenant": "red"},
                    "success_markers": ["welcome alice"],
                    "default_credentials": [("alice", "wonderland")],
                    "max_default_credential_attempts": 1,
                },
            }
        )

        login_html = """
        <html><body>
          <form method="post" action="/login">
            <input type="text" name="emailAddress" />
            <input type="password" name="passwd" />
          </form>
        </body></html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/login":
                return httpx.Response(200, text=login_html, headers={"content-type": "text/html"})
            if request.method == "POST" and request.url.path == "/login":
                body = request.content.decode()
                assert "emailAddress=alice" in body
                assert "passwd=wonderland" in body
                assert "tenant=red" in body
                return httpx.Response(200, text="Welcome Alice")
            return httpx.Response(404, text="not found")

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test"))

        assert len(findings) == 1
        assert findings[0].title == "Default credentials work: alice:wonderland"

    asyncio.run(scenario())
