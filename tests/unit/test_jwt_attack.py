"""Tests for JWT attack auth bootstrap behavior."""

import asyncio
import base64
import json

import httpx

from nightowl.models.target import Target
from nightowl.modules.web.jwt_attack import JWTAttackPlugin


def _b64url(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _token() -> str:
    return f"{_b64url({'alg': 'HS256', 'typ': 'JWT'})}.{_b64url({'sub': '1'})}.sig"


def test_jwt_attack_uses_configured_login_form_to_extract_token():
    async def scenario():
        token = _token()
        plugin = JWTAttackPlugin(
            config={
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

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/":
                return httpx.Response(200, text="<html>home</html>", headers={"content-type": "text/html"})
            if request.method == "GET" and request.url.path == "/login":
                return httpx.Response(200, text=login_html, headers={"content-type": "text/html"})
            if request.method == "POST" and request.url.path == "/login":
                return httpx.Response(
                    200,
                    text=f'{{"token":"{token}"}}',
                    headers={"content-type": "application/json"},
                )
            return httpx.Response(404, text="not found")

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test/"))

        assert any(f.category == "jwt" for f in findings)

    asyncio.run(scenario())


def test_jwt_attack_respects_configured_login_field_names_and_extra_fields():
    async def scenario():
        token = _token()
        plugin = JWTAttackPlugin(
            config={
                "auth": {
                    "login_url": "http://example.test/signin",
                    "username": "alice@example.test",
                    "password": "secret",
                    "username_field": "emailAddress",
                    "password_field": "passwd",
                    "extra_form_fields": {"tenant": "red"},
                }
            }
        )

        login_html = """
        <html><body>
          <form method="post" action="/signin">
            <input type="text" name="emailAddress" />
            <input type="password" name="passwd" />
          </form>
        </body></html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/":
                return httpx.Response(200, text="<html>home</html>", headers={"content-type": "text/html"})
            if request.method == "GET" and request.url.path == "/signin":
                return httpx.Response(200, text=login_html, headers={"content-type": "text/html"})
            if request.method == "POST" and request.url.path == "/signin":
                body = request.content.decode()
                assert "emailAddress=alice%40example.test" in body
                assert "passwd=secret" in body
                assert "tenant=red" in body
                return httpx.Response(
                    200,
                    text=f'{{"token":"{token}"}}',
                    headers={"content-type": "application/json"},
                )
            return httpx.Response(404, text="not found")

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test/"))

        assert any(f.category == "jwt" for f in findings)

    asyncio.run(scenario())
