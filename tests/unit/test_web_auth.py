"""Tests for shared web auth helpers."""

import asyncio

import httpx

from nightowl.utils.web_auth import (
    bootstrap_login_from_config,
    extract_login_form,
    login_successful,
    submit_login_form,
)


def test_extract_login_form_finds_username_password_and_hidden_fields():
    html = """
    <html><body>
      <form method="post" action="/login">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <input type="hidden" name="csrf_token" value="abc123" />
      </form>
    </body></html>
    """

    form = extract_login_form(html, "http://example.test/login")

    assert form is not None
    assert form.action_url == "http://example.test/login"
    assert form.username_field == "username"
    assert form.password_field == "password"
    assert form.hidden_fields["csrf_token"] == "abc123"


def test_login_successful_detects_redirect_and_non_error_body():
    redirect_resp = httpx.Response(302, headers={"location": "/dashboard"}, text="")
    assert login_successful(redirect_resp) is True

    failed_resp = httpx.Response(200, text="invalid credentials")
    assert login_successful(failed_resp) is False


def test_login_successful_respects_configured_markers_and_status_codes():
    success_resp = httpx.Response(200, text="welcome back alice")
    assert login_successful(
        success_resp,
        auth_config={"success_markers": ["welcome back"]},
    ) is True

    failure_resp = httpx.Response(200, text="totp required")
    assert login_successful(
        failure_resp,
        auth_config={"failure_markers": ["totp required"]},
    ) is False

    accepted_resp = httpx.Response(204, text="")
    assert login_successful(
        accepted_resp,
        auth_config={"success_status_codes": [204]},
    ) is True


def test_submit_login_form_posts_hidden_and_credentials():
    async def scenario():
        html = """
        <html><body>
          <form method="post" action="/login">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="csrf_token" value="abc123" />
          </form>
        </body></html>
        """
        form = extract_login_form(html, "http://example.test/login")

        def handler(request: httpx.Request) -> httpx.Response:
            body = request.content.decode()
            assert "username=admin" in body
            assert "password=secret" in body
            assert "csrf_token=abc123" in body
            return httpx.Response(302, headers={"location": "/dashboard"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://example.test")
        response = await submit_login_form(client, form, "admin", "secret")
        assert response.status_code == 302
        await client.aclose()

    asyncio.run(scenario())


def test_extract_login_form_respects_configured_field_names():
    html = """
    <html><body>
      <form method="post" action="/signin">
        <input type="text" name="emailAddress" />
        <input type="password" name="passwd" />
      </form>
    </body></html>
    """

    form = extract_login_form(
        html,
        "http://example.test/signin",
        auth_config={"username_field": "emailAddress", "password_field": "passwd"},
    )

    assert form is not None
    assert form.username_field == "emailAddress"
    assert form.password_field == "passwd"


def test_bootstrap_login_from_config_can_apply_non_form_auth_material():
    async def scenario():
        client = httpx.AsyncClient()
        await bootstrap_login_from_config(
            client,
            {
                "bearer_token": "abc.def.ghi",
                "api_key": "secret-key",
                "api_key_header": "X-API-Key",
                "headers": {"X-Tenant": "acme"},
                "cookies": {"session": "cookie123"},
            },
        )
        assert client.headers["Authorization"] == "Bearer abc.def.ghi"
        assert client.headers["X-API-Key"] == "secret-key"
        assert client.headers["X-Tenant"] == "acme"
        assert client.cookies.get("session") == "cookie123"
        await client.aclose()

    asyncio.run(scenario())


def test_submit_login_form_includes_extra_form_fields():
    async def scenario():
        html = """
        <html><body>
          <form method="post" action="/login">
            <input type="text" name="emailAddress" />
            <input type="password" name="passwd" />
          </form>
        </body></html>
        """
        form = extract_login_form(
            html,
            "http://example.test/login",
            auth_config={"username_field": "emailAddress", "password_field": "passwd"},
        )

        def handler(request: httpx.Request) -> httpx.Response:
            body = request.content.decode()
            assert "emailAddress=admin" in body
            assert "passwd=secret" in body
            assert "tenant=red" in body
            return httpx.Response(302, headers={"location": "/dashboard"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://example.test")
        response = await submit_login_form(
            client,
            form,
            "admin",
            "secret",
            auth_config={"extra_form_fields": {"tenant": "red"}},
        )
        assert response.status_code == 302
        await client.aclose()

    asyncio.run(scenario())
