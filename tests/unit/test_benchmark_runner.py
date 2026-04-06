"""Tests for benchmark runner helpers."""

from pathlib import Path

import yaml

from benchmarks.runner import (
    aggregate_benchmark_findings,
    BenchmarkResult,
    check_target_reachable,
    build_benchmark_command,
    dedupe_findings,
    extract_hidden_input,
    parse_findings_count,
    render_session_markdown,
    resolve_target_url,
    slugify,
    split_focus_findings,
    write_benchmark_config,
)


def test_slugify_normalizes_target_name():
    assert slugify("Juice Shop") == "juice-shop"
    assert slugify("WebGoat / Demo") == "webgoat-demo"


def test_resolve_target_url_uses_defaults_and_override():
    assert resolve_target_url("dvwa") == "http://127.0.0.1:8081"
    assert resolve_target_url("nightowl-lab") == "http://127.0.0.1:8084"
    assert resolve_target_url("cors-lab") == "http://127.0.0.1:8085"
    assert resolve_target_url("custom", explicit_url="http://localhost:9000") == "http://localhost:9000"


def test_build_benchmark_command_uses_core_scan():
    assert build_benchmark_command(
        ".venv/bin/python",
        "benchmarks/runs/test/benchmark-config.yaml",
        "http://127.0.0.1:8081",
    ) == [
        ".venv/bin/python",
        "-m",
        "nightowl.cli.main",
        "--config",
        "benchmarks/runs/test/benchmark-config.yaml",
        "scan",
        "web",
        "http://127.0.0.1:8081",
        "--core",
    ]


def test_parse_findings_count_from_cli_output():
    assert parse_findings_count("Scan complete: 12 findings") == 12
    assert parse_findings_count("nothing useful here") is None


def test_render_session_markdown_includes_command_and_artifacts():
    result = BenchmarkResult(
        target_name="dvwa",
        profile_description="Root-page benchmark for DVWA without authenticated workflow coverage.",
        expected_modules=["header-analyzer", "dir-bruteforce"],
        probe_urls=["http://127.0.0.1:8081/", "http://127.0.0.1:8081/login.php"],
        url="http://127.0.0.1:8081",
        command=[".venv/bin/python", "-m", "nightowl.cli.main", "scan", "web", "http://127.0.0.1:8081", "--core"],
        commit="abc1234",
        started_at="2026-03-26T15:00:00+00:00",
        finished_at="2026-03-26T15:00:10+00:00",
        duration_seconds=10.0,
        return_code=0,
        findings_count=5,
        scan_id="scan-123",
        stdout_path="benchmarks/runs/run/stdout.txt",
        stderr_path="benchmarks/runs/run/stderr.txt",
        raw_session_path="benchmarks/runs/run/metadata.json",
        session_markdown_path="benchmarks/sessions/2026-03-26-dvwa-abc1234.md",
        findings_json_path="benchmarks/runs/run/findings.json",
        stats_json_path="benchmarks/runs/run/stats.json",
        verdicts_json_path="benchmarks/runs/run/verdicts.json",
        focus_findings_json_path="benchmarks/runs/run/focus-findings.json",
        focus_stats_json_path="benchmarks/runs/run/focus-stats.json",
        report_markdown_path="benchmarks/runs/run/reports/nightowl-scan-123.md",
        report_html_path="benchmarks/runs/run/reports/nightowl-scan-123.html",
        focus_report_markdown_path="benchmarks/runs/run/reports/nightowl-scan-123-focus.md",
        focus_report_html_path="benchmarks/runs/run/reports/nightowl-scan-123-focus.html",
        probe_results_path="benchmarks/runs/run/probe-results.json",
        environment="test-env",
        reachable=True,
        preflight_error=None,
    )

    markdown = render_session_markdown(result)

    assert "abc1234" in markdown
    assert "`header-analyzer`" in markdown
    assert "Findings count: 5" in markdown
    assert "benchmarks/runs/run/stdout.txt" in markdown
    assert "Reachable: yes" in markdown
    assert "Scan ID: scan-123" in markdown
    assert "Expected Core Signal" in markdown
    assert "Probe URLs" in markdown
    assert "Verdicts JSON" in markdown
    assert "Focus Findings JSON" in markdown
    assert "Focus HTML report" in markdown


def test_check_target_reachable_reports_failure_for_closed_port():
    reachable, error = check_target_reachable("http://127.0.0.1:9", timeout=0.1)

    assert reachable is False
    assert error


def test_extract_hidden_input_supports_single_and_double_quotes():
    html = """
    <input type="hidden" name="user_token" value="abc123" />
    <input type='hidden' name='another_token' value='def456' />
    """

    assert extract_hidden_input(html, "user_token") == "abc123"
    assert extract_hidden_input(html, "another_token") == "def456"


def test_write_benchmark_config_uses_host_scope_not_full_url(tmp_path: Path):
    config_path = write_benchmark_config(
        tmp_path,
        "http://127.0.0.1:8081/test?q=1",
        base_config_path=tmp_path / "missing.yaml",
    )

    raw = yaml.safe_load(config_path.read_text())

    assert raw["scope"]["allowed_hosts"] == ["127.0.0.1"]
    assert raw["scope"]["allowed_ips"] == ["127.0.0.1"]


def test_write_benchmark_config_keeps_domain_scope_in_allowed_hosts_only(tmp_path: Path):
    config_path = write_benchmark_config(
        tmp_path,
        "http://demo.example.com:8080/path",
        base_config_path=tmp_path / "missing.yaml",
    )

    raw = yaml.safe_load(config_path.read_text())

    assert raw["scope"]["allowed_hosts"] == ["demo.example.com"]
    assert raw["scope"]["allowed_ips"] == []


def test_aggregate_benchmark_findings_collapses_header_findings_across_probes():
    findings = [
        {
            "module_name": "header-analyzer",
            "title": "Missing Security Header: X-Frame-Options",
            "evidence": "Header 'X-Frame-Options' absent in response from http://127.0.0.1:8081/",
            "metadata": {
                "url": "http://127.0.0.1:8081/",
                "benchmark_probe_url": "http://127.0.0.1:8081/",
            },
        },
        {
            "module_name": "header-analyzer",
            "title": "Missing Security Header: X-Frame-Options",
            "evidence": "Header 'X-Frame-Options' absent in response from http://127.0.0.1:8081/login.php",
            "metadata": {
                "url": "http://127.0.0.1:8081/login.php",
                "benchmark_probe_url": "http://127.0.0.1:8081/login.php",
            },
        },
        {
            "module_name": "xss-scanner",
            "title": "Reflected XSS in parameter 'name'",
            "evidence": "URL: http://127.0.0.1:8081/vulnerabilities/xss_r/?name=%3Cscript%3E",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8081/vulnerabilities/xss_r/?name=test",
            },
        },
    ]

    aggregated = aggregate_benchmark_findings(findings)

    assert len(aggregated) == 2
    header = next(item for item in aggregated if item["module_name"] == "header-analyzer")
    assert header["metadata"]["aggregation_scope"] == "benchmark-application"
    assert header["metadata"]["aggregated_probe_count"] == 2
    assert len(header["metadata"]["aggregated_probe_urls"]) == 2
    assert "Observed across benchmark probes:" in header["evidence"]


def test_aggregate_benchmark_findings_collapses_duplicate_dir_discoveries_across_probes():
    findings = [
        {
            "module_name": "dir-bruteforce",
            "title": "Discovered: /.htaccess (403)",
            "evidence": "URL: http://127.0.0.1:8081/.htaccess",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8081/",
            },
        },
        {
            "module_name": "dir-bruteforce",
            "title": "Discovered: /.htaccess (403)",
            "evidence": "URL: http://127.0.0.1:8081/.htaccess",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8081/vulnerabilities/xss_r/?name=test",
            },
        },
        {
            "module_name": "dir-bruteforce",
            "title": "Discovered: /robots.txt (200)",
            "evidence": "URL: http://127.0.0.1:8081/robots.txt",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8081/",
            },
        },
    ]

    aggregated = aggregate_benchmark_findings(findings)

    assert len(aggregated) == 2
    htaccess = next(item for item in aggregated if ".htaccess" in item["title"])
    assert htaccess["metadata"]["aggregation_scope"] == "benchmark-discovery"
    assert htaccess["metadata"]["aggregated_probe_count"] == 2
    assert len(htaccess["metadata"]["aggregated_probe_urls"]) == 2


def test_dedupe_findings_keeps_cors_findings_distinct_per_probe():
    findings = [
        {
            "module_name": "cors-checker",
            "title": "CORS allows dangerous methods: DELETE, PATCH, PUT",
            "evidence": "Allowed methods: DELETE, PATCH, PUT",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8085/wildcard-credentials",
            },
        },
        {
            "module_name": "cors-checker",
            "title": "CORS allows dangerous methods: DELETE, PATCH, PUT",
            "evidence": "Allowed methods: DELETE, PATCH, PUT",
            "metadata": {
                "benchmark_probe_url": "http://127.0.0.1:8085/dangerous-methods",
            },
        },
    ]

    deduped = dedupe_findings(findings)

    assert len(deduped) == 2


def test_split_focus_findings_separates_expected_modules():
    findings = [
        {"module_name": "cors-checker", "title": "CORS: Wildcard with credentials"},
        {"module_name": "header-analyzer", "title": "Missing Security Header: X-Frame-Options"},
        {"module_name": "ssl-analyzer", "title": "No TLS — target uses plain HTTP"},
    ]

    focus, background = split_focus_findings(findings, ["cors-checker"])

    assert focus == [findings[0]]
    assert background == findings[1:]
