"""Tests for boolean-based blind SQLi detection and time-based verification."""

import asyncio
import time

import httpx
import pytest

from nightowl.models.target import Target
from nightowl.modules.web.sqli_scanner import SQLiScannerPlugin


class TestResponseSimilarity:
    def test_identical_strings(self):
        assert SQLiScannerPlugin._response_similarity("hello", "hello") == 1.0

    def test_empty_strings(self):
        assert SQLiScannerPlugin._response_similarity("", "") == 1.0

    def test_completely_different(self):
        sim = SQLiScannerPlugin._response_similarity("aaaaaa", "zzzzzz")
        assert sim < 0.3

    def test_similar_strings(self):
        a = "<html><body>Results: 10 items found</body></html>"
        b = "<html><body>Results: 10 items found</body></html>"
        assert SQLiScannerPlugin._response_similarity(a, b) == 1.0

    def test_partially_similar(self):
        a = "<html><body>Results: 10 items found</body></html>"
        b = "<html><body>No results found</body></html>"
        sim = SQLiScannerPlugin._response_similarity(a, b)
        assert 0.3 < sim < 0.95


class TestBooleanBasedBlindDetection:
    def test_boolean_blind_sqli_detected(self):
        """When true/false conditions produce different responses, detect SQLi."""
        true_body = "<html>Showing 10 results for user...</html>"
        false_body = "<html>No results found</html>"
        normal_body = "<html>Showing 10 results for user...</html>"

        def handler(request: httpx.Request) -> httpx.Response:
            query = str(request.url.params.get("id", ""))
            if "1'='1" in query or "1=1" in query:
                return httpx.Response(200, text=true_body)
            elif "1'='2" in query or "1=2" in query:
                return httpx.Response(200, text=false_body)
            return httpx.Response(200, text=normal_body)

        async def scenario():
            plugin = SQLiScannerPlugin(config={"boolean_diff_threshold": 0.1})
            transport = httpx.MockTransport(handler)

            def fake_client(**_kwargs):
                return httpx.AsyncClient(transport=transport, base_url="http://test.local")

            plugin.create_http_client = fake_client
            target = Target(host="http://test.local?id=1")
            return await plugin.run(target)

        findings = asyncio.run(scenario())
        boolean_findings = [f for f in findings if "Boolean-Based" in f.title]
        assert len(boolean_findings) == 1
        assert boolean_findings[0].metadata["technique"] == "boolean-based-blind"

    def test_no_false_positive_when_responses_identical(self):
        """When true and false conditions produce same response, no detection."""
        body = "<html>Same page always</html>"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=body)

        async def scenario():
            plugin = SQLiScannerPlugin()
            transport = httpx.MockTransport(handler)

            def fake_client(**_kwargs):
                return httpx.AsyncClient(transport=transport, base_url="http://test.local")

            plugin.create_http_client = fake_client
            target = Target(host="http://test.local?id=1")
            return await plugin.run(target)

        findings = asyncio.run(scenario())
        boolean_findings = [f for f in findings if "Boolean-Based" in f.title]
        assert len(boolean_findings) == 0


class TestTimingSignal:
    def test_strong_timing_signal(self):
        assert SQLiScannerPlugin._timing_signal_is_strong(
            baseline_time=0.1,
            elapsed=3.5,
            expected_delay=3,
            threshold=2.5,
        ) is True

    def test_weak_timing_signal(self):
        assert SQLiScannerPlugin._timing_signal_is_strong(
            baseline_time=0.1,
            elapsed=1.0,
            expected_delay=3,
            threshold=2.5,
        ) is False

    def test_slow_network_not_flagged(self):
        # If baseline is already slow, timing diff should not trigger
        assert SQLiScannerPlugin._timing_signal_is_strong(
            baseline_time=2.5,
            elapsed=3.0,
            expected_delay=3,
            threshold=2.5,
        ) is False
