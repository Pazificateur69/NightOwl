"""Comprehensive tests for CORS Checker."""

import asyncio

import httpx
import pytest

from nightowl.models.target import Target
from nightowl.modules.web.cors_checker import CORSCheckerPlugin


def _make_cors_handler(
    reflect_origin: bool = False,
    allow_credentials: bool = False,
    wildcard: bool = False,
    allow_null: bool = False,
    allow_methods: str = "GET",
):
    """Create an httpx mock handler with configurable CORS behaviour."""

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"content-type": "text/html"}
        origin = request.headers.get("origin", "")

        if wildcard:
            headers["access-control-allow-origin"] = "*"
        elif reflect_origin and origin and origin != "null":
            headers["access-control-allow-origin"] = origin
        elif allow_null and origin == "null":
            headers["access-control-allow-origin"] = "null"

        if allow_credentials:
            headers["access-control-allow-credentials"] = "true"

        if request.method == "OPTIONS":
            headers["access-control-allow-methods"] = allow_methods

        return httpx.Response(200, text="<html>ok</html>", headers=headers)

    return handler


def _run_cors_check(handler, **plugin_kwargs) -> list:
    async def scenario():
        plugin = CORSCheckerPlugin(config=plugin_kwargs)
        transport = httpx.MockTransport(handler)

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url="http://test.local")

        plugin.create_http_client = fake_client
        return await plugin.run(Target(host="http://test.local"))

    return asyncio.run(scenario())


class TestCORSReflectsArbitraryOrigins:
    def test_reflected_origins_found(self):
        handler = _make_cors_handler(reflect_origin=True)
        findings = _run_cors_check(handler)
        titles = [f.title for f in findings]
        assert any("reflects arbitrary origins" in t for t in titles)

    def test_reflected_with_credentials_is_high(self):
        handler = _make_cors_handler(reflect_origin=True, allow_credentials=True)
        findings = _run_cors_check(handler)
        reflected = [f for f in findings if "reflects arbitrary origins" in f.title]
        assert len(reflected) == 1
        assert reflected[0].severity.value == "high"


class TestWildcardWithCredentials:
    def test_wildcard_plus_credentials_detected(self):
        handler = _make_cors_handler(wildcard=True, allow_credentials=True)
        findings = _run_cors_check(handler)
        wc = [f for f in findings if "Wildcard with credentials" in f.title]
        assert len(wc) == 1
        assert wc[0].severity.value == "high"


class TestNullOrigin:
    def test_null_origin_detected(self):
        handler = _make_cors_handler(allow_null=True)
        findings = _run_cors_check(handler)
        null_findings = [f for f in findings if "null origin" in f.title]
        assert len(null_findings) == 1


class TestDangerousMethods:
    def test_dangerous_methods_flagged(self):
        handler = _make_cors_handler(
            reflect_origin=True,
            allow_methods="GET, POST, PUT, DELETE, PATCH",
        )
        findings = _run_cors_check(handler)
        method_findings = [f for f in findings if "dangerous methods" in f.title]
        assert len(method_findings) == 1
        assert "PUT" in method_findings[0].title
        assert "DELETE" in method_findings[0].title

    def test_dangerous_methods_not_flagged_without_broad_origin_exposure(self):
        def handler(request: httpx.Request) -> httpx.Response:
            headers = {"content-type": "text/html"}
            if request.method == "OPTIONS":
                headers["access-control-allow-origin"] = "*"
                headers["access-control-allow-methods"] = "GET, POST, PUT, DELETE, PATCH"
            return httpx.Response(200, text="<html>ok</html>", headers=headers)

        findings = _run_cors_check(handler)

        method_findings = [f for f in findings if "dangerous methods" in f.title]
        assert len(method_findings) == 0

    def test_dangerous_methods_flagged_from_preflight_reflection_even_if_get_is_safe(self):
        def handler(request: httpx.Request) -> httpx.Response:
            headers = {"content-type": "text/html"}
            origin = request.headers.get("origin", "")
            if request.method == "OPTIONS":
                headers["access-control-allow-origin"] = origin
                headers["access-control-allow-methods"] = "GET, POST, PUT, DELETE, PATCH"
            else:
                headers["access-control-allow-origin"] = "https://myapp.com"
            return httpx.Response(200, text="<html>ok</html>", headers=headers)

        findings = _run_cors_check(handler)

        method_findings = [f for f in findings if "dangerous methods" in f.title]
        assert len(method_findings) == 1


class TestSafeConfiguration:
    def test_no_cors_headers_no_findings(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>ok</html>")

        findings = _run_cors_check(handler)
        assert len(findings) == 0

    def test_specific_allowed_origin_not_flagged(self):
        def handler(request: httpx.Request) -> httpx.Response:
            headers = {"access-control-allow-origin": "https://myapp.com"}
            return httpx.Response(200, text="ok", headers=headers)

        findings = _run_cors_check(handler)
        reflected = [f for f in findings if "reflects" in f.title]
        assert len(reflected) == 0
