"""Tests for benchmark summary helpers."""

from benchmarks.summary import (
    delta_lines,
    finding_family,
    latest_results_by_target,
    latest_and_previous_results_by_target,
    load_focus_findings_for_result,
    module_counts,
    observation_lines,
    render_markdown_summary,
    split_focus_module_counts,
)


def test_latest_results_by_target_keeps_newest_run():
    results = [
        {"target_name": "dvwa", "started_at": "2026-03-26T15:00:00+00:00", "return_code": 2},
        {"target_name": "dvwa", "started_at": "2026-03-26T16:00:00+00:00", "return_code": 0},
        {"target_name": "webgoat", "started_at": "2026-03-26T15:30:00+00:00", "return_code": 2},
    ]

    latest = latest_results_by_target(results)

    assert len(latest) == 2
    assert latest[0]["target_name"] == "dvwa"
    assert latest[0]["return_code"] == 0


def test_render_markdown_summary_shows_latest_targets():
    summary = render_markdown_summary(
        [
            {
                "target_name": "dvwa",
                "reachable": False,
                "return_code": 2,
                "findings_count": None,
                "started_at": "2026-03-26T16:00:00+00:00",
                "session_markdown_path": "benchmarks/sessions/2026-03-26-dvwa-abc1234.md",
                "findings_json_path": "",
            },
            {
                "target_name": "webgoat",
                "reachable": True,
                "return_code": 0,
                "findings_count": 7,
                "started_at": "2026-03-26T16:05:00+00:00",
                "session_markdown_path": "benchmarks/sessions/2026-03-26-webgoat-abc1234.md",
                "findings_json_path": "",
            },
        ]
    )

    assert "| dvwa | no | 2 | n/a |" in summary
    assert "| webgoat | yes | 0 | 7 |" in summary


def test_latest_and_previous_results_by_target_returns_two_most_recent_runs():
    pairs = latest_and_previous_results_by_target(
        [
            {"target_name": "dvwa", "started_at": "2026-03-26T15:00:00+00:00", "findings_count": 10},
            {"target_name": "dvwa", "started_at": "2026-03-26T16:00:00+00:00", "findings_count": 12},
            {"target_name": "dvwa", "started_at": "2026-03-26T17:00:00+00:00", "findings_count": 11},
        ]
    )

    assert pairs["dvwa"]["latest"]["findings_count"] == 11
    assert pairs["dvwa"]["previous"]["findings_count"] == 12


def test_render_markdown_summary_handles_empty_state():
    assert "No benchmark artifacts found" in render_markdown_summary([])


def test_module_counts_aggregates_by_module_name():
    counts = module_counts(
        [
            {"module_name": "header-analyzer"},
            {"module_name": "header-analyzer"},
            {"module_name": "dir-bruteforce"},
        ]
    )

    assert counts == {"header-analyzer": 2, "dir-bruteforce": 1}


def test_module_counts_support_deduplication_modes():
    findings = [
        {
            "module_name": "header-analyzer",
            "title": "Missing Security Header: X-Frame-Options",
            "evidence": "Header 'X-Frame-Options' absent in response from http://127.0.0.1:8081/",
        },
        {
            "module_name": "header-analyzer",
            "title": "Missing Security Header: X-Frame-Options",
            "evidence": "Header 'X-Frame-Options' absent in response from http://127.0.0.1:8081/login.php",
        },
        {
            "module_name": "dir-bruteforce",
            "title": "Discovered: /robots.txt (200)",
            "evidence": "URL: http://127.0.0.1:8081/robots.txt\nStatus: 200",
        },
        {
            "module_name": "dir-bruteforce",
            "title": "Discovered: /robots.txt (403)",
            "evidence": "URL: http://127.0.0.1:8081/robots.txt\nStatus: 403",
        },
    ]

    assert module_counts(findings) == {"header-analyzer": 2, "dir-bruteforce": 2}
    assert module_counts(findings, dedupe_by="title") == {
        "header-analyzer": 1,
        "dir-bruteforce": 2,
    }
    assert module_counts(findings, dedupe_by="family") == {
        "header-analyzer": 1,
        "dir-bruteforce": 1,
    }


def test_split_focus_module_counts_separates_expected_and_background_modules():
    findings = [
        {"module_name": "cors-checker", "title": "CORS: Wildcard with credentials", "metadata": {"benchmark_probe_url": "http://127.0.0.1:8085/wildcard-credentials"}},
        {"module_name": "header-analyzer", "title": "Missing Security Header: X-Frame-Options"},
        {"module_name": "ssl-analyzer", "title": "No TLS — target uses plain HTTP"},
    ]

    focus, background = split_focus_module_counts(findings, "cors-lab", dedupe_by="family")

    assert focus == {"cors-checker": 1}
    assert background == {"header-analyzer": 1, "ssl-analyzer": 1}


def test_finding_family_normalizes_noisy_probe_specific_variants():
    assert (
        finding_family(
            {
                "module_name": "header-analyzer",
                "title": "Missing Security Header: Content-Security-Policy",
                "evidence": "Header 'Content-Security-Policy' absent in response from http://127.0.0.1:8082/robots.txt",
            }
        )
        == "header-analyzer:missing-header:Content-Security-Policy"
    )
    assert (
        finding_family(
            {
                "module_name": "dir-bruteforce",
                "title": "Discovered: /robots.txt (403)",
                "evidence": "URL: http://127.0.0.1:8082/robots.txt\nStatus: 403",
            }
        )
        == "dir-bruteforce:discovered-path:/robots.txt"
    )
    assert (
        finding_family(
            {
                "module_name": "sqli-scanner",
                "title": "SQL Injection (Error-Based) in 'userid'",
                "metadata": {
                    "technique": "error-based",
                    "action_url": "http://127.0.0.1:8083/WebGoat/SqlInjection/assignment5b",
                    "param": "userid",
                },
            }
        )
        == "sqli-scanner:error-based:assignment5b:userid"
    )
    assert (
        finding_family(
            {
                "module_name": "cors-checker",
                "title": "CORS: Wildcard with credentials",
                "metadata": {
                    "benchmark_probe_url": "http://127.0.0.1:8085/wildcard-credentials",
                },
            }
        )
        == "cors-checker:wildcard-credentials:/wildcard-credentials"
    )


def test_observation_lines_note_silent_modules():
    lines = observation_lines(
        {"target_name": "dvwa"},
        [{"module_name": "header-analyzer"}, {"module_name": "dir-bruteforce"}],
    )

    assert any("strongest signal came from `header-analyzer`" in line for line in lines)
    assert any("deduplicated signal still centers" in line for line in lines)
    assert any("covered expected modules" in line for line in lines)
    assert any("unexercised on this profile" in line for line in lines)


def test_render_markdown_summary_shows_raw_and_deduplicated_views():
    summary = render_markdown_summary(
        [
            {
                "target_name": "dvwa",
                "reachable": True,
                "return_code": 0,
                "findings_count": 4,
                "started_at": "2026-03-26T16:00:00+00:00",
                "session_markdown_path": "benchmarks/sessions/2026-03-26-dvwa-abc1234.md",
                "findings_json_path": "tests/fixtures/benchmarks/dvwa-findings.json",
                "verdicts_json_path": "tests/fixtures/benchmarks/dvwa-verdicts.json",
            }
        ]
    )

    assert "| dvwa | yes | 0 | 4 | 2 |" in summary
    assert "`dvwa` raw:" in summary
    assert "`dvwa` dedup by family:" in summary
    assert "## Verdicts" in summary
    assert "`confirmed_hit`=0" in summary


def test_render_markdown_summary_shows_focus_and_background_modules():
    summary = render_markdown_summary(
        [
            {
                "target_name": "cors-lab",
                "reachable": True,
                "return_code": 0,
                "findings_count": 3,
                "started_at": "2026-04-02T08:00:00+00:00",
                "session_markdown_path": "benchmarks/sessions/2026-04-02-cors-lab-abc1234.md",
                "findings_json_path": "tests/fixtures/benchmarks/cors-lab-findings.json",
                "verdicts_json_path": "tests/fixtures/benchmarks/cors-lab-verdicts.json",
            }
        ]
    )

    assert "`cors-lab` focus modules:" in summary
    assert "`cors-checker`=1" in summary
    assert "`cors-lab` background modules:" in summary


def test_load_focus_findings_for_result_reads_focus_artifact(tmp_path):
    findings_path = tmp_path / "focus-findings.json"
    findings_path.write_text('[{"module_name":"cors-checker","title":"CORS: Wildcard with credentials"}]')

    findings = load_focus_findings_for_result({"focus_findings_json_path": str(findings_path)})

    assert findings == [{"module_name": "cors-checker", "title": "CORS: Wildcard with credentials"}]


def test_render_markdown_summary_mentions_focus_artifact_when_available():
    summary = render_markdown_summary(
        [
            {
                "target_name": "cors-lab",
                "reachable": True,
                "return_code": 0,
                "findings_count": 3,
                "started_at": "2026-04-02T08:00:00+00:00",
                "session_markdown_path": "benchmarks/sessions/2026-04-02-cors-lab-abc1234.md",
                "findings_json_path": "tests/fixtures/benchmarks/cors-lab-findings.json",
                "focus_findings_json_path": "tests/fixtures/benchmarks/cors-lab-findings.json",
                "verdicts_json_path": "tests/fixtures/benchmarks/cors-lab-verdicts.json",
            }
        ]
    )

    assert "`cors-lab` focus artifact:" in summary


def test_delta_lines_report_changes_between_runs(tmp_path):
    previous_findings = tmp_path / "previous-findings.json"
    previous_verdicts = tmp_path / "previous-verdicts.json"
    latest_findings = tmp_path / "latest-findings.json"
    latest_verdicts = tmp_path / "latest-verdicts.json"

    previous_findings.write_text(
        '[{"module_name":"header-analyzer","title":"Missing Security Header: X-Frame-Options","evidence":"Header absent"}]'
    )
    previous_verdicts.write_text(
        '{"verdict_counts":{"confirmed_hit":0,"expected_hit":1,"missed_expected":1,"likely_false_positive":0,"inconclusive":0}}'
    )
    latest_findings.write_text(
        '[{"module_name":"header-analyzer","title":"Missing Security Header: X-Frame-Options","evidence":"Header absent"},{"module_name":"sqli-scanner","title":"SQL Injection (Error-Based) in \\"q\\"","evidence":"Status: 500"}]'
    )
    latest_verdicts.write_text(
        '{"verdict_counts":{"confirmed_hit":1,"expected_hit":1,"missed_expected":0,"likely_false_positive":0,"inconclusive":0}}'
    )

    lines = delta_lines(
        [
            {
                "target_name": "juice-shop",
                "started_at": "2026-03-26T16:00:00+00:00",
                "findings_count": 1,
                "findings_json_path": str(previous_findings),
                "verdicts_json_path": str(previous_verdicts),
            },
            {
                "target_name": "juice-shop",
                "started_at": "2026-03-26T17:00:00+00:00",
                "findings_count": 2,
                "findings_json_path": str(latest_findings),
                "verdicts_json_path": str(latest_verdicts),
            },
        ]
    )

    assert any("findings +1 (1 -> 2)" in line for line in lines)
    assert any("confirmed_hit +1 (0 -> 1)" in line for line in lines)
    assert any("missed_expected -1 (1 -> 0)" in line for line in lines)
    assert any("`sqli-scanner` 0->1" in line for line in lines)


def test_render_markdown_summary_shows_quiet_expectations_and_violations(tmp_path):
    findings = tmp_path / "findings.json"
    verdicts = tmp_path / "verdicts.json"
    findings.write_text("[]")
    verdicts.write_text(
        '{"verdict_counts":{"confirmed_hit":0,"expected_hit":0,"quiet_expected":4,"quiet_violation":1,"missed_expected":0,"likely_false_positive":1,"inconclusive":0},"quiet_violations":[{"module_name":"xss-scanner","probe_path":"/xss/json"}]}'
    )

    summary = render_markdown_summary(
        [
            {
                "target_name": "nightowl-lab",
                "reachable": True,
                "return_code": 0,
                "findings_count": 0,
                "started_at": "2026-03-27T10:20:00+00:00",
                "session_markdown_path": "benchmarks/sessions/2026-03-27-nightowl-lab-abc1234.md",
                "findings_json_path": str(findings),
                "verdicts_json_path": str(verdicts),
            }
        ]
    )

    assert "`quiet_expected`=4" in summary
    assert "`quiet_violation`=1" in summary
    assert "quiet violations" in summary
