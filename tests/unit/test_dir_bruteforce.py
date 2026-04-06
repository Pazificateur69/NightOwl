"""Comprehensive tests for directory bruteforce scanner."""

import asyncio
from unittest.mock import patch

import httpx
import pytest

from nightowl.models.target import Target
from nightowl.modules.web.dir_bruteforce import DirBruteforcePlugin


class TestSoft404Detection:
    def test_same_status_similar_length_is_baseline(self):
        assert DirBruteforcePlugin._looks_like_baseline(404, 100, 404, 100) is True

    def test_same_status_same_hash_is_baseline(self):
        assert DirBruteforcePlugin._looks_like_baseline(
            404, 100, 404, 100,
            body_hash="abc123", baseline_body_hash="abc123",
        ) is True

    def test_different_hash_not_baseline(self):
        assert DirBruteforcePlugin._looks_like_baseline(
            404, 100, 404, 100,
            body_hash="abc123", baseline_body_hash="def456",
        ) is False

    def test_different_status_not_baseline(self):
        assert DirBruteforcePlugin._looks_like_baseline(200, 100, 404, 100) is False

    def test_tight_5_percent_threshold(self):
        # 5% of 1000 = 50 bytes tolerance
        assert DirBruteforcePlugin._looks_like_baseline(404, 1050, 404, 1000) is True
        assert DirBruteforcePlugin._looks_like_baseline(404, 1060, 404, 1000) is False

    def test_minimum_16_byte_tolerance(self):
        assert DirBruteforcePlugin._looks_like_baseline(404, 16, 404, 0) is True
        assert DirBruteforcePlugin._looks_like_baseline(404, 17, 404, 0) is False

    def test_none_baseline_returns_false(self):
        assert DirBruteforcePlugin._looks_like_baseline(404, 100, None, None) is False


class TestPathClassification:
    def test_admin_paths_are_sensitive(self):
        category, sev, _, _ = DirBruteforcePlugin._classify_path("/admin", 200)
        assert category == "sensitive"
        assert sev.value == "medium"

    def test_backup_paths_are_sensitive(self):
        category, sev, _, _ = DirBruteforcePlugin._classify_path("/backup.zip", 200)
        assert category == "sensitive"

    def test_env_paths_are_sensitive(self):
        category, sev, _, _ = DirBruteforcePlugin._classify_path("/.env", 200)
        assert category == "sensitive"

    def test_public_path_is_info(self):
        category, sev, _, _ = DirBruteforcePlugin._classify_path("/assets", 200)
        assert category == "public"
        assert sev.value == "info"

    def test_unknown_path(self):
        category, _, _, _ = DirBruteforcePlugin._classify_path("/random-page", 200)
        assert category == "unknown"


class TestWordlistLoading:
    def test_default_wordlist(self):
        plugin = DirBruteforcePlugin()
        words = plugin._load_wordlist()
        assert len(words) > 0
        assert "admin" in words

    def test_custom_list_from_config(self):
        plugin = DirBruteforcePlugin(config={"wordlist": ["custom1", "custom2"]})
        words = plugin._load_wordlist()
        assert words == ["custom1", "custom2"]

    def test_missing_file_falls_back_to_defaults(self):
        plugin = DirBruteforcePlugin(config={"wordlist": "/nonexistent/wordlist.txt"})
        words = plugin._load_wordlist()
        assert len(words) > 0  # falls back to COMMON_DIRS


class TestBodyHash:
    def test_same_content_same_hash(self):
        h1 = DirBruteforcePlugin._body_hash(b"hello world")
        h2 = DirBruteforcePlugin._body_hash(b"hello world")
        assert h1 == h2

    def test_different_content_different_hash(self):
        h1 = DirBruteforcePlugin._body_hash(b"hello")
        h2 = DirBruteforcePlugin._body_hash(b"world")
        assert h1 != h2


class TestRunWithMockHTTP:
    def test_discovers_real_directory(self):
        baseline_body = b"<html>Not Found</html>"

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if "/admin" in path:
                return httpx.Response(200, content=b"<html>Admin Panel</html>")
            # All random paths return the same 404
            return httpx.Response(404, content=baseline_body)

        async def scenario():
            plugin = DirBruteforcePlugin(config={"wordlist": ["admin", "foo", "bar"]})
            transport = httpx.MockTransport(handler)

            def fake_client(**_kwargs):
                return httpx.AsyncClient(transport=transport, base_url="http://test.local")

            plugin.create_http_client = fake_client
            return await plugin.run(Target(host="http://test.local"))

        findings = asyncio.run(scenario())
        admin_findings = [f for f in findings if "admin" in f.title.lower() or "admin" in f.evidence.lower()]
        assert len(admin_findings) >= 1

    def test_soft_404_filtered_out(self):
        soft_404_body = b"<html>The page was not found, sorry!</html>"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=soft_404_body)

        async def scenario():
            plugin = DirBruteforcePlugin(config={"wordlist": ["secret", "hidden"]})
            transport = httpx.MockTransport(handler)

            def fake_client(**_kwargs):
                return httpx.AsyncClient(transport=transport, base_url="http://test.local")

            plugin.create_http_client = fake_client
            return await plugin.run(Target(host="http://test.local"))

        findings = asyncio.run(scenario())
        assert len(findings) == 0
