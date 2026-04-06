"""Tests for report generation."""

from nightowl.reporting.generator import ReportGenerator
from nightowl.reporting.html_report import generate_html_report, _esc, _svg_donut
from nightowl.reporting.markdown_report import generate_markdown_report


class TestHTMLReport:
    def test_xss_prevention(self):
        """User-controlled values should be HTML-escaped."""
        assert _esc("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
        assert _esc('"onclick="alert(1)') == '&quot;onclick=&quot;alert(1)'

    def test_generates_valid_html(self):
        context = {
            "findings": [
                {"title": "Test XSS", "severity": "high", "target": "x.com",
                 "cvss_score": 6.1, "module_name": "xss-scanner",
                 "finding_state": "suspected", "confidence_score": 0.83,
                 "metadata": {"module_maturity": "recommended"},
                 "evidence": "payload reflected", "remediation": "encode output"},
            ],
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "title": "Test Report",
            "scan_id": "abc-123",
            "timestamp": "2025-01-01",
        }
        html = generate_html_report(context)
        assert "<!DOCTYPE html>" in html
        assert "Test Report" in html
        assert "Test XSS" in html
        assert "SUSPECTED" in html
        assert "0.83" in html
        # No external CDN references
        assert "cdn.jsdelivr.net" not in html
        assert "chart.js" not in html.lower()

    def test_svg_donut_no_data(self):
        svg = _svg_donut({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        assert "No data" in svg

    def test_svg_donut_with_data(self):
        svg = _svg_donut({"critical": 1, "high": 3, "medium": 2, "low": 0, "info": 5})
        assert "Critical" in svg
        assert "High" in svg
        assert "<svg" in svg

    def test_malicious_input_escaped(self):
        """Report should not be vulnerable to XSS via finding data."""
        context = {
            "findings": [
                {"title": '<img src=x onerror=alert(1)>', "severity": "high",
                 "target": "x.com", "cvss_score": 0, "module_name": "test",
                 "evidence": "<script>steal()</script>", "remediation": "fix"},
            ],
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        }
        html = generate_html_report(context)
        assert "<img src=x onerror" not in html
        assert "&lt;img src=x onerror" in html
        assert "<script>steal()" not in html

    def test_benchmark_context_is_rendered_in_html_report(self):
        context = {
            "findings": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "benchmark_target": "juice-shop",
            "benchmark_profile_description": "Multi-probe benchmark",
            "benchmark_artifact_scope": "focus-only",
            "benchmark_probe_urls": ["http://127.0.0.1:8082/", "http://127.0.0.1:8082/rest/products/search?q=apple"],
            "benchmark_verdict_counts": {
                "confirmed_hit": 1,
                "expected_hit": 2,
                "quiet_expected": 4,
                "quiet_violation": 0,
                "missed_expected": 0,
                "likely_false_positive": 3,
                "inconclusive": 4,
            },
            "benchmark_top_modules": [
                {"name": "header-analyzer", "count": 20},
                {"name": "sqli-scanner", "count": 1},
            ],
        }

        html = generate_html_report(context)
        assert "Benchmark Context" in html
        assert "juice-shop" in html
        assert "confirmed_hit" in html
        assert "quiet_expected" in html
        assert "header-analyzer" in html
        assert "focus-only" in html


class TestMarkdownReport:
    def test_benchmark_context_is_rendered_in_markdown_report(self):
        context = {
            "findings": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "benchmark_target": "dvwa",
            "benchmark_profile_description": "DVWA unauthenticated profile",
            "benchmark_artifact_scope": "raw",
            "benchmark_probe_urls": ["http://127.0.0.1:8081/", "http://127.0.0.1:8081/login.php"],
            "benchmark_verdict_counts": {
                "confirmed_hit": 0,
                "expected_hit": 5,
                "quiet_expected": 4,
                "quiet_violation": 1,
                "missed_expected": 1,
                "likely_false_positive": 2,
                "inconclusive": 3,
            },
            "benchmark_top_modules": [
                {"name": "header-analyzer", "count": 25},
            ],
        }

        markdown = generate_markdown_report(context)
        assert "## Benchmark Context" in markdown
        assert "**Target:** dvwa" in markdown
        assert "**Artifact Scope:** raw" in markdown
        assert "**Quiet Expected:** 4" in markdown
        assert "**Likely False Positives:** 2" in markdown
        assert "`header-analyzer`: 25 findings" in markdown


class TestReportGenerator:
    def test_filename_suffix_prevents_raw_and_focus_report_collisions(self, tmp_path):
        generator = ReportGenerator(output_dir=str(tmp_path))
        findings = []
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        raw_path = generator.generate(
            "scan-1234",
            findings,
            stats,
            fmt="md",
            filename_suffix="raw",
        )
        focus_path = generator.generate(
            "scan-1234",
            findings,
            stats,
            fmt="md",
            filename_suffix="focus",
        )

        assert raw_path != focus_path
        assert raw_path.endswith("-raw.md")
        assert focus_path.endswith("-focus.md")
