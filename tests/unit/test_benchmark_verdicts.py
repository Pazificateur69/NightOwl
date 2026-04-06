"""Tests for benchmark verdict classification."""

from benchmarks.profiles import get_profile
from benchmarks.verdicts import classify_finding, summarize_verdicts


def test_classify_finding_marks_reviewed_juice_shop_sqli_as_confirmed():
    profile = get_profile("juice-shop")
    finding = {
        "module_name": "sqli-scanner",
        "title": "SQL Injection (Error-Based) in 'q'",
        "evidence": "URL: http://127.0.0.1:8082/rest/products/search?q=%27+OR+%271%27%3D%271%27+--",
    }

    verdict = classify_finding(profile, finding)

    assert verdict.verdict == "confirmed_hit"
    assert "explicitly reviewed and confirmed" in verdict.rationale


def test_summarize_verdicts_tracks_expected_and_missed_families():
    profile = get_profile("dvwa")
    findings = [
        {
            "module_name": "header-analyzer",
            "title": "Missing Security Header: X-Frame-Options",
            "evidence": "Header 'X-Frame-Options' absent in response from http://127.0.0.1:8081/",
        },
        {
            "module_name": "dir-bruteforce",
            "title": "Discovered: /robots.txt (200)",
            "evidence": "URL: http://127.0.0.1:8081/robots.txt\nStatus: 200",
        },
    ]

    summary = summarize_verdicts(profile, findings)

    assert summary["verdict_counts"]["expected_hit"] == 2
    assert summary["verdict_counts"]["missed_expected"] >= 1
    assert any(
        item["family"] == "header-analyzer:missing-header:Content-Security-Policy"
        for item in summary["missed_expected"]
    )


def test_classify_finding_marks_deprecated_x_xss_header_as_likely_false_positive():
    profile = get_profile("dvwa")
    finding = {
        "module_name": "header-analyzer",
        "title": "Missing Security Header: X-XSS-Protection",
        "evidence": "Header 'X-XSS-Protection' absent in response from http://127.0.0.1:8081/",
    }

    verdict = classify_finding(profile, finding)

    assert verdict.verdict == "likely_false_positive"
    assert "deprecated in modern browsers" in verdict.rationale


def test_classify_finding_marks_common_public_dir_discovery_as_likely_false_positive():
    profile = get_profile("juice-shop")
    finding = {
        "module_name": "dir-bruteforce",
        "title": "Discovered: /assets (301)",
        "evidence": "URL: http://127.0.0.1:8082/assets\nStatus: 301",
    }

    verdict = classify_finding(profile, finding)

    assert verdict.verdict == "likely_false_positive"
    assert "`/assets`" in verdict.rationale


def test_classify_finding_marks_safe_context_xss_probe_as_likely_false_positive():
    profile = get_profile("nightowl-lab")
    finding = {
        "module_name": "xss-scanner",
        "title": "Reflected XSS in parameter 'q'",
        "metadata": {
            "benchmark_probe_url": "http://127.0.0.1:8084/xss/json?q=hello",
        },
        "evidence": "URL: http://127.0.0.1:8084/xss/json?q=%3Cscript%3Ealert(1)%3C/script%3E",
    }

    verdict = classify_finding(profile, finding)

    assert verdict.verdict == "likely_false_positive"
    assert "should stay quiet" in verdict.rationale


def test_classify_finding_marks_plain_http_ssl_signal_as_expected_for_http_lab_profiles():
    profile = get_profile("webgoat")
    finding = {
        "module_name": "ssl-analyzer",
        "title": "No TLS — target uses plain HTTP",
        "evidence": "Scheme: http, Host: 127.0.0.1, Port: 8083",
    }

    verdict = classify_finding(profile, finding)

    assert verdict.verdict == "expected_hit"
    assert "expected signal" in verdict.rationale


def test_summarize_verdicts_tracks_quiet_expectations_for_nightowl_lab():
    profile = get_profile("nightowl-lab")
    findings = [
        {
            "module_name": "xss-scanner",
            "title": "Reflected XSS in parameter 'q'",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8084/xss/reflected?q=hello",
            },
            "evidence": "URL: http://127.0.0.1:8084/xss/reflected?q=%3Cscript%3Ealert(1)%3C/script%3E",
        },
        {
            "module_name": "sqli-scanner",
            "title": "SQL Injection (Error-Based) in 'q'",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8084/sql/error?q=apple",
            },
            "evidence": "Status: 500",
        },
    ]

    summary = summarize_verdicts(profile, findings)

    assert summary["verdict_counts"]["quiet_expected"] == 4
    assert summary["verdict_counts"]["quiet_violation"] == 0
    assert len(summary["quiet_expected"]) == 4


def test_summarize_verdicts_tracks_quiet_violation_when_safe_route_fires():
    profile = get_profile("nightowl-lab")
    findings = [
        {
            "module_name": "xss-scanner",
            "title": "Reflected XSS in parameter 'q'",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8084/xss/json?q=hello",
            },
            "evidence": "URL: http://127.0.0.1:8084/xss/json?q=%3Cscript%3Ealert(1)%3C/script%3E",
        },
    ]

    summary = summarize_verdicts(profile, findings)

    assert summary["verdict_counts"]["quiet_expected"] == 3
    assert summary["verdict_counts"]["quiet_violation"] == 1
    assert summary["quiet_violations"][0]["probe_path"] == "/xss/json"


def test_summarize_verdicts_tracks_quiet_expectation_for_cors_allowlist():
    profile = get_profile("cors-lab")

    summary = summarize_verdicts(profile, [])

    assert summary["verdict_counts"]["quiet_expected"] == 1
    assert summary["verdict_counts"]["quiet_violation"] == 0
    assert summary["quiet_expected"][0]["probe_path"] == "/allowlist"
