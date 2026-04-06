"""Comprehensive tests for header analyzer."""

import asyncio

import httpx
import pytest

from nightowl.models.target import Target
from nightowl.modules.web.header_analyzer import HeaderAnalyzerPlugin


def _make_handler(response_headers: dict, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text="<html>ok</html>", headers=response_headers)
    return handler


def _run_header_check(response_headers: dict, url: str = "https://test.local") -> list:
    async def scenario():
        plugin = HeaderAnalyzerPlugin()
        transport = httpx.MockTransport(_make_handler(response_headers))

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url=url)

        plugin.create_http_client = fake_client
        return await plugin.run(Target(host=url))

    return asyncio.run(scenario())


class TestMissingSecurityHeaders:
    def test_all_headers_missing(self):
        findings = _run_header_check({})
        missing = [f for f in findings if "Missing Security Header" in f.title]
        # Should flag at least X-Frame-Options, X-Content-Type-Options, CSP, HSTS
        assert len(missing) >= 4
        assert all("X-XSS-Protection" not in f.title for f in missing)

    def test_hsts_not_flagged_on_http(self):
        findings = _run_header_check({}, url="http://test.local")
        hsts_findings = [f for f in findings if "Strict-Transport-Security" in f.title]
        assert len(hsts_findings) == 0

    def test_hsts_flagged_on_https(self):
        findings = _run_header_check({}, url="https://test.local")
        hsts_findings = [f for f in findings if "Strict-Transport-Security" in f.title]
        assert len(hsts_findings) == 1

    def test_present_header_not_flagged(self):
        findings = _run_header_check({"x-frame-options": "DENY"})
        xfo = [f for f in findings if "X-Frame-Options" in f.title]
        assert len(xfo) == 0


class TestInfoLeakHeaders:
    def test_server_header_detected(self):
        findings = _run_header_check({"server": "Apache/2.4.41"})
        server_findings = [f for f in findings if "Server" in f.title]
        assert len(server_findings) == 1
        assert "Apache/2.4.41" in server_findings[0].evidence

    def test_x_powered_by_detected(self):
        findings = _run_header_check({"x-powered-by": "Express"})
        powered = [f for f in findings if "X-Powered-By" in f.title]
        assert len(powered) == 1


class TestAllSecureHeaders:
    def test_fully_secured_returns_only_info_or_none(self):
        secure_headers = {
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "x-xss-protection": "1; mode=block",
        }
        findings = _run_header_check(secure_headers, url="https://test.local")
        missing = [f for f in findings if "Missing" in f.title]
        assert len(missing) == 0


class TestLegacyHeaderMode:
    def test_legacy_x_xss_protection_only_reported_when_enabled(self):
        async def scenario():
            plugin = HeaderAnalyzerPlugin(config={"include_legacy_headers": True})
            transport = httpx.MockTransport(_make_handler({}))

            def fake_client(**_kwargs):
                return httpx.AsyncClient(transport=transport, base_url="https://test.local")

            plugin.create_http_client = fake_client
            return await plugin.run(Target(host="https://test.local"))

        findings = asyncio.run(scenario())

        assert any("X-XSS-Protection" in f.title for f in findings)


class TestIsHttpsUrl:
    def test_https_url(self):
        assert HeaderAnalyzerPlugin._is_https_url("https://example.com") is True

    def test_http_url(self):
        assert HeaderAnalyzerPlugin._is_https_url("http://example.com") is False

    def test_no_scheme(self):
        assert HeaderAnalyzerPlugin._is_https_url("example.com") is False
