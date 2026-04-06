"""Focused tests for Week 2 core-module hardening helpers."""

from nightowl.models.finding import FindingState, Severity
from nightowl.modules.network.port_deep_scan import DeepPortScanPlugin
from nightowl.modules.web.cors_checker import CORSCheckerPlugin
from nightowl.modules.web.dir_bruteforce import DirBruteforcePlugin
from nightowl.modules.web.header_analyzer import HeaderAnalyzerPlugin
from nightowl.modules.web.ssl_analyzer import SSLAnalyzerPlugin
from nightowl.modules.web.sqli_scanner import SQLiScannerPlugin


class TestHeaderAnalyzer:
    def test_hsts_only_for_https(self):
        assert HeaderAnalyzerPlugin._is_https_url("https://example.com") is True
        assert HeaderAnalyzerPlugin._is_https_url("http://example.com") is False


class TestSSLAnalyzer:
    def test_weak_protocol_detection(self):
        assert SSLAnalyzerPlugin._is_weak_protocol("TLSv1.0") is True
        assert SSLAnalyzerPlugin._is_weak_protocol("TLSv1.1") is True
        assert SSLAnalyzerPlugin._is_weak_protocol("TLSv1.2") is False
        assert SSLAnalyzerPlugin._is_weak_protocol("TLSv1.3") is False


class TestDirBruteforce:
    def test_soft_404_detection(self):
        assert DirBruteforcePlugin._looks_like_baseline(404, 1000, 404, 1010) is True
        assert DirBruteforcePlugin._looks_like_baseline(200, 1000, 404, 1010) is False
        assert DirBruteforcePlugin._looks_like_baseline(404, 500, 404, 1010) is False

    def test_normalize_base_url_strips_query_and_fragment(self):
        assert (
            DirBruteforcePlugin._normalize_base_url("http://127.0.0.1:8084/xss/reflected?q=hello#frag")
            == "http://127.0.0.1:8084/xss/reflected"
        )

    def test_path_classification_marks_public_routes_as_low_signal(self):
        kind, severity, state, confidence = DirBruteforcePlugin._classify_path("assets", 301)
        assert kind == "public"
        assert severity == Severity.INFO
        assert state == FindingState.INFO
        assert confidence == 0.4

    def test_path_classification_marks_interesting_routes(self):
        kind, severity, state, confidence = DirBruteforcePlugin._classify_path("robots.txt", 200)
        assert kind == "interesting"
        assert severity == Severity.LOW
        assert state == FindingState.SUSPECTED
        assert confidence == 0.72

    def test_path_classification_marks_sensitive_routes(self):
        kind, severity, state, confidence = DirBruteforcePlugin._classify_path(".htaccess", 403)
        assert kind == "sensitive"
        assert severity == Severity.MEDIUM
        assert state == FindingState.SUSPECTED
        assert confidence == 0.88

    def test_refinement_downgrades_public_html_pages(self):
        kind, severity, state, confidence, reason = DirBruteforcePlugin._refine_classification(
            "login",
            "public",
            Severity.LOW,
            FindingState.SUSPECTED,
            0.78,
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            body_preview="<html><title>Login</title></html>",
        )
        assert kind == "public"
        assert severity == Severity.INFO
        assert state == FindingState.INFO
        assert confidence == 0.35
        assert "generic HTML page" in reason

    def test_refinement_escalates_structured_sensitive_exposure(self):
        kind, severity, state, confidence, reason = DirBruteforcePlugin._refine_classification(
            "config",
            "sensitive",
            Severity.LOW,
            FindingState.SUSPECTED,
            0.76,
            status_code=200,
            headers={"content-type": "application/json"},
            body_preview='{"api_key":"secret"}',
        )
        assert kind == "sensitive"
        assert severity == Severity.MEDIUM
        assert state == FindingState.SUSPECTED
        assert confidence >= 0.9
        assert "structured content" in reason or "application/json" in reason

    def test_refinement_downgrades_redirect_to_login(self):
        kind, severity, state, confidence, reason = DirBruteforcePlugin._refine_classification(
            "admin",
            "sensitive",
            Severity.LOW,
            FindingState.SUSPECTED,
            0.76,
            status_code=302,
            headers={"location": "/login"},
            body_preview="",
        )
        assert kind == "public"
        assert severity == Severity.INFO
        assert state == FindingState.INFO
        assert confidence == 0.35
        assert "redirects to a common public route" in reason


class TestSQLiScanner:
    def test_timing_signal_strength(self):
        assert SQLiScannerPlugin._timing_signal_is_strong(0.2, 5.4, 5, 4.0) is True
        assert SQLiScannerPlugin._timing_signal_is_strong(4.5, 5.4, 5, 4.0) is False
        assert SQLiScannerPlugin._timing_signal_is_strong(0.2, 2.0, 5, 4.0) is False


class TestCORSChecker:
    def test_plugin_class_instantiates(self):
        plugin = CORSCheckerPlugin()
        assert plugin.name == "cors-checker"


class TestDeepPortScan:
    def test_risky_service_classification(self):
        severity, state, confidence = DeepPortScanPlugin._classify_open_service("redis", {})
        assert severity == Severity.MEDIUM
        assert state == FindingState.CONFIRMED
        assert confidence >= 0.95

    def test_nse_vuln_output_escalates_finding(self):
        severity, state, confidence = DeepPortScanPlugin._classify_open_service(
            "http",
            {"vulners": "Host appears vulnerable to CVE-2023-0001"},
        )
        assert severity == Severity.HIGH
        assert state == FindingState.SUSPECTED
        assert confidence == 0.9
