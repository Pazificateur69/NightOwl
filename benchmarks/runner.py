"""Run reproducible local benchmark sessions for NightOwl core modules."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
from uuid import uuid4

import httpx
import yaml

from nightowl.db.database import Database
from nightowl.reporting.generator import ReportGenerator

from benchmarks.profiles import get_profile, resolve_probe_urls
from benchmarks.summary import finding_family, module_counts
from benchmarks.verdicts import summarize_verdicts

DEFAULT_OUTPUT_DIR = Path("benchmarks/runs")
DEFAULT_SESSIONS_DIR = Path("benchmarks/sessions")
DEFAULT_NIGHTOWL_PYTHON = Path(".venv/bin/python")
DEFAULT_BASE_CONFIG = Path("configs/default.yaml")
DEFAULT_TARGETS = {
    "dvwa": "http://127.0.0.1:8081",
    "juice-shop": "http://127.0.0.1:8082",
    "webgoat": "http://127.0.0.1:8083/WebGoat",
    "nightowl-lab": "http://127.0.0.1:8084",
    "cors-lab": "http://127.0.0.1:8085",
}
CORE_MODULES = [
    "header-analyzer",
    "xss-scanner",
    "sqli-scanner",
    "cors-checker",
    "ssl-analyzer",
    "port-scanner",
    "deep-port-scan",
    "dir-bruteforce",
]


@dataclass
class BenchmarkResult:
    target_name: str
    profile_description: str | None
    expected_modules: list[str]
    probe_urls: list[str]
    url: str
    command: list[str]
    commit: str
    started_at: str
    finished_at: str
    duration_seconds: float
    return_code: int
    findings_count: int | None
    scan_id: str | None
    stdout_path: str
    stderr_path: str
    raw_session_path: str
    session_markdown_path: str
    findings_json_path: str | None
    stats_json_path: str | None
    verdicts_json_path: str | None
    focus_findings_json_path: str | None
    focus_stats_json_path: str | None
    report_markdown_path: str | None
    report_html_path: str | None
    focus_report_markdown_path: str | None
    focus_report_html_path: str | None
    probe_results_path: str | None
    environment: str
    reachable: bool
    preflight_error: str | None
    auth_mode: str | None = None
    auth_notes: list[str] = field(default_factory=list)


@dataclass
class BenchmarkAuthContext:
    mode: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    probe_urls: list[str] | None = None
    notes: list[str] = field(default_factory=list)


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def resolve_target_url(target_name: str, explicit_url: str | None = None) -> str:
    if explicit_url:
        return explicit_url
    if target_name not in DEFAULT_TARGETS:
        raise ValueError(f"Unknown target '{target_name}'. Provide --url for custom targets.")
    return DEFAULT_TARGETS[target_name]


def extract_hidden_input(html: str, field_name: str) -> str | None:
    patterns = (
        rf'name="{re.escape(field_name)}"\s+value="([^"]+)"',
        rf"name='{re.escape(field_name)}'\s+value='([^']+)'",
        rf'value="([^"]+)"\s+name="{re.escape(field_name)}"',
        rf"value='([^']+)'\s+name='{re.escape(field_name)}'",
    )
    for pattern in patterns:
        match = re.search(pattern, html, re.I)
        if match:
            return match.group(1)
    return None


def bootstrap_target_auth(
    target_name: str,
    resolved_url: str,
) -> BenchmarkAuthContext | None:
    if target_name == "dvwa":
        base = resolved_url.rstrip("/") + "/"
        with httpx.Client(follow_redirects=True, verify=False, timeout=20) as client:
            setup_url = urljoin(base, "setup.php")
            setup_page = client.get(setup_url)
            setup_token = extract_hidden_input(setup_page.text, "user_token")
            if setup_token:
                client.post(
                    setup_url,
                    data={"create_db": "Create / Reset Database", "user_token": setup_token},
                )

            login_url = urljoin(base, "login.php")
            login_page = client.get(login_url)
            login_token = extract_hidden_input(login_page.text, "user_token")
            login_data = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
            }
            if login_token:
                login_data["user_token"] = login_token
            login_response = client.post(login_url, data=login_data)
            verify = client.get(urljoin(base, "index.php"))
            if "login.php" in str(verify.url) or "setup.php" in str(verify.url):
                raise RuntimeError("DVWA authenticated bootstrap failed to reach the application shell.")

            cookies = dict(client.cookies)
            cookies.setdefault("security", "low")
            return BenchmarkAuthContext(
                mode="dvwa-default-admin",
                cookies=cookies,
                probe_urls=[
                    urljoin(base, ""),
                    urljoin(base, "instructions.php"),
                    urljoin(base, "vulnerabilities/xss_r/?name=test"),
                    urljoin(base, "vulnerabilities/sqli/?id=1&Submit=Submit"),
                    urljoin(base, "robots.txt"),
                ],
                notes=[
                    f"Bootstrapped DVWA setup via {setup_url}.",
                    f"Authenticated to DVWA as admin via {login_url}.",
                    f"Post-login shell reached at {verify.url}.",
                    f"Final login response landed at {login_response.url}.",
                ],
            )

    if target_name == "webgoat":
        base = resolved_url.rstrip("/")
        username = f"nightowl-{uuid4().hex[:6]}"
        password = "owl12345"
        with httpx.Client(follow_redirects=True, verify=False, timeout=20) as client:
            register_url = urljoin(base + "/", "register.mvc")
            login_url = urljoin(base + "/", "login")
            client.post(
                register_url,
                data={
                    "username": username,
                    "password": password,
                    "matchingPassword": password,
                    "agree": "agree",
                },
            )
            login_response = client.post(
                login_url,
                data={"username": username, "password": password},
            )
            verify = client.get(urljoin(base + "/", "service/lessonmenu.mvc"))
            if verify.status_code != 200:
                raise RuntimeError("WebGoat authenticated bootstrap failed to reach lesson menu.")

            return BenchmarkAuthContext(
                mode="webgoat-disposable-user",
                cookies=dict(client.cookies),
                probe_urls=[
                    urljoin(base + "/", ""),
                    urljoin(base + "/", "welcome.mvc"),
                    urljoin(base + "/", "start.mvc?lang=en"),
                    urljoin(base + "/", "service/lessonmenu.mvc"),
                    urljoin(base + "/", "SqlInjection.lesson"),
                    urljoin(base + "/", "CrossSiteScripting.lesson"),
                    urljoin(
                        base + "/",
                        "CrossSiteScripting/attack5a?QTY1=1&QTY2=1&QTY3=1&QTY4=1&field1=test&field2=111",
                    ),
                ],
                notes=[
                    f"Created disposable WebGoat user {username}.",
                    f"Authenticated to WebGoat via {login_url}.",
                    f"Lesson menu reached at {verify.url}.",
                    f"Final login response landed at {login_response.url}.",
                ],
            )

    return None


def build_benchmark_command(python_bin: str, config_path: str, url: str) -> list[str]:
    return [python_bin, "-m", "nightowl.cli.main", "--config", config_path, "scan", "web", url, "--core"]


def parse_findings_count(stdout: str) -> int | None:
    match = re.search(r"Scan complete:\s+(\d+)\s+findings", stdout)
    if match:
        return int(match.group(1))
    return None


def get_git_commit() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return proc.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def is_git_dirty() -> bool:
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        )
        return bool(proc.stdout.strip())
    except Exception:
        return False


def check_target_reachable(url: str, timeout: float = 5.0) -> tuple[bool, str | None]:
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, verify=False) as client:
            response = client.get(url)
            return True, f"HTTP {response.status_code}"
    except Exception as exc:
        return False, str(exc)


def write_benchmark_config(
    run_dir: Path,
    target_url: str,
    *,
    base_config_path: Path = DEFAULT_BASE_CONFIG,
    headers: dict | None = None,
    cookies: dict | None = None,
) -> Path:
    raw = {}
    if base_config_path.exists():
        raw = yaml.safe_load(base_config_path.read_text()) or {}

    raw["db_path"] = str(run_dir / "benchmark.db")
    raw["output_dir"] = str(run_dir / "reports")
    if headers:
        raw["headers"] = headers
    if cookies:
        raw["cookies"] = cookies

    scope = raw.setdefault("scope", {})
    allowed_hosts = scope.setdefault("allowed_hosts", [])
    allowed_ips = scope.setdefault("allowed_ips", [])
    parsed = urlparse(target_url)
    scope_host = parsed.hostname or target_url

    if scope_host not in allowed_hosts:
        allowed_hosts.append(scope_host)

    try:
        import ipaddress
        ipaddress.ip_address(scope_host)
    except ValueError:
        pass
    else:
        if scope_host not in allowed_ips:
            allowed_ips.append(scope_host)

    config_path = run_dir / "benchmark-config.yaml"
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return config_path


async def collect_scan_artifacts(db_path: str) -> tuple[str | None, list[dict], dict]:
    db = Database(db_path)
    await db.init()
    scans = await db.get_scans()
    if not scans:
        return None, [], {}
    latest_scan = scans[0]
    scan_id = latest_scan["id"]
    findings = await db.get_findings(scan_id)
    stats = await db.get_finding_stats(scan_id)
    return scan_id, findings, stats


def aggregate_stats(findings: list[dict]) -> dict[str, int]:
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "info")
        if severity in stats:
            stats[severity] += 1
    return stats


def split_focus_findings(findings: list[dict], expected_modules: list[str]) -> tuple[list[dict], list[dict]]:
    expected = set(expected_modules)
    if not expected:
        return [], findings

    focus = [finding for finding in findings if finding.get("module_name") in expected]
    background = [finding for finding in findings if finding.get("module_name") not in expected]
    return focus, background


def dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for finding in findings:
        metadata = finding.get("metadata", {})
        key = (
            finding.get("module_name", ""),
            finding_family(finding),
            metadata.get("benchmark_probe_url", "") or finding.get("evidence", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def aggregate_benchmark_findings(findings: list[dict]) -> list[dict]:
    aggregated: list[dict] = []
    grouped_headers: dict[tuple[str, str], list[dict]] = {}
    grouped_dirs: dict[tuple[str, str], list[dict]] = {}

    for finding in findings:
        module_name = finding.get("module_name", "")
        if module_name == "header-analyzer":
            key = (module_name, finding_family(finding))
            grouped_headers.setdefault(key, []).append(finding)
            continue
        if module_name == "dir-bruteforce":
            key = (module_name, finding_family(finding))
            grouped_dirs.setdefault(key, []).append(finding)
            continue
        aggregated.append(finding)

    for (_module_name, _family), group in grouped_headers.items():
        base = json.loads(json.dumps(group[0]))
        probe_urls = sorted(
            {
                item.get("metadata", {}).get("benchmark_probe_url", "")
                for item in group
                if item.get("metadata", {}).get("benchmark_probe_url")
            }
        )
        response_urls = sorted(
            {
                item.get("metadata", {}).get("url", "")
                for item in group
                if item.get("metadata", {}).get("url")
            }
        )
        metadata = base.setdefault("metadata", {})
        metadata["aggregation_scope"] = "benchmark-application"
        metadata["aggregated_probe_count"] = len(probe_urls) or len(group)
        metadata["aggregated_probe_urls"] = probe_urls
        metadata["aggregated_response_urls"] = response_urls

        evidence_lines = [base.get("evidence", "").strip()] if base.get("evidence") else []
        if probe_urls:
            evidence_lines.append(
                "Observed across benchmark probes:\n" + "\n".join(f"- {url}" for url in probe_urls)
            )
        base["evidence"] = "\n\n".join(line for line in evidence_lines if line).strip()
        aggregated.append(base)

    for (_module_name, _family), group in grouped_dirs.items():
        base = json.loads(json.dumps(group[0]))
        if len(group) == 1:
            aggregated.append(base)
            continue

        probe_urls = sorted(
            {
                item.get("metadata", {}).get("benchmark_probe_url", "")
                for item in group
                if item.get("metadata", {}).get("benchmark_probe_url")
            }
        )
        metadata = base.setdefault("metadata", {})
        metadata["aggregation_scope"] = "benchmark-discovery"
        metadata["aggregated_probe_count"] = len(probe_urls) or len(group)
        metadata["aggregated_probe_urls"] = probe_urls

        evidence_lines = [base.get("evidence", "").strip()] if base.get("evidence") else []
        if probe_urls:
            evidence_lines.append(
                "Observed across benchmark probes:\n" + "\n".join(f"- {url}" for url in probe_urls)
            )
        base["evidence"] = "\n\n".join(line for line in evidence_lines if line).strip()
        aggregated.append(base)

    return aggregated


def render_session_markdown(result: BenchmarkResult) -> str:
    status = "passed" if result.return_code == 0 else "failed"
    findings_display = (
        str(result.findings_count) if result.findings_count is not None else "unparsed"
    )
    return f"""# Benchmark Session

## Session Info

- Date: {result.started_at[:10]}
- Commit: {result.commit}
- Operator: {os.getenv("USER", "unknown")}
- Environment: {result.environment}
- Status: {status}
- Reachable: {"yes" if result.reachable else "no"}
- Auth Mode: {result.auth_mode or "none"}

## Target

- Target: {result.target_name}
- Profile: {result.profile_description or "custom"}
- URL: {result.url}
- Probes: {len(result.probe_urls)}

## Modules Run

{chr(10).join(f"- `{module}`" for module in CORE_MODULES)}

## Expected Core Signal

{chr(10).join(f"- `{module}`" for module in result.expected_modules) if result.expected_modules else "- none declared"}

## Probe URLs

{chr(10).join(f"- `{probe}`" for probe in result.probe_urls)}

## Auth Notes

{chr(10).join(f"- {note}" for note in result.auth_notes) if result.auth_notes else "- none"}

## Execution

- Command: `{' '.join(result.command)}`
- Start: {result.started_at}
- End: {result.finished_at}
- Duration: {result.duration_seconds:.2f}s
- Return code: {result.return_code}
- Findings count: {findings_display}
- Scan ID: {result.scan_id or "unavailable"}
- Preflight: {result.preflight_error or "ok"}

## Artifacts

- Raw stdout: `{result.stdout_path}`
- Raw stderr: `{result.stderr_path}`
- Metadata JSON: `{result.raw_session_path}`
- Session Markdown: `{result.session_markdown_path}`
- Findings JSON: `{result.findings_json_path or "unavailable"}`
- Stats JSON: `{result.stats_json_path or "unavailable"}`
- Verdicts JSON: `{result.verdicts_json_path or "unavailable"}`
- Focus Findings JSON: `{result.focus_findings_json_path or "unavailable"}`
- Focus Stats JSON: `{result.focus_stats_json_path or "unavailable"}`
- Markdown report: `{result.report_markdown_path or "unavailable"}`
- HTML report: `{result.report_html_path or "unavailable"}`
- Focus Markdown report: `{result.focus_report_markdown_path or "unavailable"}`
- Focus HTML report: `{result.focus_report_html_path or "unavailable"}`
- Probe Results JSON: `{result.probe_results_path or "unavailable"}`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
"""


def run_benchmark(
    target_name: str,
    *,
    url: str | None = None,
    python_bin: str = str(DEFAULT_NIGHTOWL_PYTHON),
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    sessions_dir: Path = DEFAULT_SESSIONS_DIR,
) -> BenchmarkResult:
    resolved_url = resolve_target_url(target_name, explicit_url=url)
    commit = get_git_commit()
    dirty = is_git_dirty()
    profile = get_profile(target_name)
    auth_context = bootstrap_target_auth(target_name, resolved_url)
    probe_urls = (
        auth_context.probe_urls
        if auth_context and auth_context.probe_urls
        else resolve_probe_urls(resolved_url, profile)
    )
    started = datetime.now(timezone.utc)
    run_name = f"{started.strftime('%Y%m%d-%H%M%S')}-{slugify(target_name)}-{commit}"
    run_dir = output_dir / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    command = []
    probe_results: list[dict] = []
    combined_stdout: list[str] = []
    combined_stderr: list[str] = []
    combined_findings: list[dict] = []
    reachable = False
    preflight_error = None
    return_code = 0

    for index, probe_url in enumerate(probe_urls, start=1):
        probe_dir = run_dir / f"probe-{index:02d}"
        probe_dir.mkdir(parents=True, exist_ok=True)
        config_path = write_benchmark_config(
            probe_dir,
            probe_url,
            headers=auth_context.headers if auth_context else None,
            cookies=auth_context.cookies if auth_context else None,
        )
        probe_command = build_benchmark_command(python_bin, str(config_path), probe_url)
        if not command:
            command = probe_command

        probe_reachable, probe_preflight_error = check_target_reachable(probe_url)
        probe_record = {
            "url": probe_url,
            "reachable": probe_reachable,
            "preflight_error": probe_preflight_error,
            "return_code": None,
            "scan_id": None,
            "findings_count": 0,
        }
        if probe_reachable:
            reachable = True
            proc = subprocess.run(probe_command, capture_output=True, text=True)
            combined_stdout.append(f"## Probe: {probe_url}\n{proc.stdout}")
            combined_stderr.append(f"## Probe: {probe_url}\n{proc.stderr}")
            probe_record["return_code"] = proc.returncode
            return_code = max(return_code, proc.returncode)
            db_path = probe_dir / "benchmark.db"
            if db_path.exists():
                probe_scan_id, probe_findings, _probe_stats = asyncio.run(
                    collect_scan_artifacts(str(db_path))
                )
                probe_record["scan_id"] = probe_scan_id
                probe_record["findings_count"] = len(probe_findings)
                for finding in probe_findings:
                    finding.setdefault("metadata", {})
                    finding["metadata"]["benchmark_probe_url"] = probe_url
                combined_findings.extend(probe_findings)
        else:
            combined_stderr.append(f"## Probe: {probe_url}\nTarget preflight failed: {probe_preflight_error}\n")
            probe_record["return_code"] = 2
            return_code = max(return_code, 2)
            if preflight_error is None:
                preflight_error = probe_preflight_error
        probe_results.append(probe_record)

    if not combined_stdout:
        stdout = ""
    else:
        stdout = "\n".join(combined_stdout)
    stderr = "\n".join(combined_stderr)

    finished = datetime.now(timezone.utc)
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    metadata_path = run_dir / "metadata.json"
    session_path = run_dir / "session.md"
    session_snapshot_path = sessions_dir / f"{started.strftime('%Y-%m-%d')}-{slugify(target_name)}-{commit}.md"
    findings_json_path = run_dir / "findings.json"
    stats_json_path = run_dir / "stats.json"
    verdicts_json_path = run_dir / "verdicts.json"
    focus_findings_json_path = run_dir / "focus-findings.json"
    focus_stats_json_path = run_dir / "focus-stats.json"
    probe_results_path = run_dir / "probe-results.json"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    stdout_path.write_text(stdout)
    stderr_path.write_text(stderr)
    probe_results_path.write_text(json.dumps(probe_results, indent=2), encoding="utf-8")

    scan_id = probe_results[0]["scan_id"] if probe_results else None
    findings = aggregate_benchmark_findings(dedupe_findings(combined_findings))
    stats: dict = aggregate_stats(findings)
    verdicts = summarize_verdicts(profile, findings)
    focus_findings, background_findings = split_focus_findings(
        findings,
        list(profile.expected_modules) if profile else [],
    )
    focus_stats = aggregate_stats(focus_findings)
    report_markdown_path = None
    report_html_path = None
    focus_report_markdown_path = None
    focus_report_html_path = None
    if findings:
        findings_json_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        stats_json_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
        verdicts_json_path.write_text(json.dumps(verdicts, indent=2), encoding="utf-8")
        generator = ReportGenerator(output_dir=str(run_dir / "reports"))
        aggregate_scan_id = scan_id or f"benchmark-{uuid4()}"
        raw_counts = module_counts(findings)
        top_modules = [
            {"name": name, "count": count}
            for name, count in sorted(raw_counts.items(), key=lambda item: (-item[1], item[0]))[:3]
        ]
        extra_context = {
            "benchmark_target": target_name,
            "benchmark_profile_description": profile.description if profile else "",
            "benchmark_probe_urls": probe_urls,
            "benchmark_verdict_counts": verdicts.get("verdict_counts", {}),
            "benchmark_top_modules": top_modules,
            "benchmark_artifact_scope": "raw",
        }
        report_markdown_path = generator.generate(
            aggregate_scan_id,
            findings,
            stats,
            fmt="md",
            extra_context=extra_context,
            filename_suffix="raw",
        )
        report_html_path = generator.generate(
            aggregate_scan_id,
            findings,
            stats,
            fmt="html",
            extra_context=extra_context,
            filename_suffix="raw",
        )
        if focus_findings and background_findings:
            focus_findings_json_path.write_text(
                json.dumps(focus_findings, indent=2), encoding="utf-8"
            )
            focus_stats_json_path.write_text(json.dumps(focus_stats, indent=2), encoding="utf-8")
            focus_counts = module_counts(focus_findings)
            focus_top_modules = [
                {"name": name, "count": count}
                for name, count in sorted(focus_counts.items(), key=lambda item: (-item[1], item[0]))[:3]
            ]
            focus_context = {
                "benchmark_target": target_name,
                "benchmark_profile_description": profile.description if profile else "",
                "benchmark_probe_urls": probe_urls,
                "benchmark_verdict_counts": verdicts.get("verdict_counts", {}),
                "benchmark_top_modules": focus_top_modules,
                "benchmark_artifact_scope": "focus-only",
            }
            focus_report_markdown_path = generator.generate(
                aggregate_scan_id,
                focus_findings,
                focus_stats,
                fmt="md",
                title="NightOwl Benchmark Focus Report",
                extra_context=focus_context,
                filename_suffix="focus",
            )
            focus_report_html_path = generator.generate(
                aggregate_scan_id,
                focus_findings,
                focus_stats,
                fmt="html",
                title="NightOwl Benchmark Focus Report",
                extra_context=focus_context,
                filename_suffix="focus",
            )

    result = BenchmarkResult(
        target_name=target_name,
        profile_description=profile.description if profile else None,
        expected_modules=list(profile.expected_modules) if profile else [],
        probe_urls=probe_urls,
        url=resolved_url,
        command=command,
        commit=commit,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_seconds=(finished - started).total_seconds(),
        return_code=return_code,
        findings_count=len(findings),
        scan_id=scan_id,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        raw_session_path=str(metadata_path),
        session_markdown_path=str(session_snapshot_path),
        findings_json_path=str(findings_json_path) if findings else None,
        stats_json_path=str(stats_json_path) if stats else None,
        verdicts_json_path=str(verdicts_json_path) if findings else None,
        focus_findings_json_path=str(focus_findings_json_path) if focus_findings and background_findings else None,
        focus_stats_json_path=str(focus_stats_json_path) if focus_findings and background_findings else None,
        report_markdown_path=report_markdown_path,
        report_html_path=report_html_path,
        focus_report_markdown_path=focus_report_markdown_path,
        focus_report_html_path=focus_report_html_path,
        probe_results_path=str(probe_results_path),
        environment=(
            f"python={sys.version.split()[0]}, cwd={Path.cwd()}, dirty_worktree={dirty}"
        ),
        reachable=reachable,
        preflight_error=None if reachable else preflight_error,
        auth_mode=auth_context.mode if auth_context else None,
        auth_notes=auth_context.notes if auth_context else [],
    )

    metadata_path.write_text(json.dumps(asdict(result), indent=2))
    session_markdown = render_session_markdown(result)
    session_path.write_text(session_markdown)
    session_snapshot_path.write_text(session_markdown)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local NightOwl benchmark session.")
    parser.add_argument("target", help="Target name: dvwa, juice-shop, webgoat, or custom")
    parser.add_argument("--url", default=None, help="Override target URL")
    parser.add_argument("--python-bin", default=str(DEFAULT_NIGHTOWL_PYTHON), help="Path to Python interpreter with NightOwl installed")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for benchmark artifacts")
    parser.add_argument("--sessions-dir", default=str(DEFAULT_SESSIONS_DIR), help="Directory for benchmark session snapshots")
    args = parser.parse_args()

    result = run_benchmark(
        args.target,
        url=args.url,
        python_bin=args.python_bin,
        output_dir=Path(args.output_dir),
        sessions_dir=Path(args.sessions_dir),
    )
    print(json.dumps(asdict(result), indent=2))
    return result.return_code


if __name__ == "__main__":
    raise SystemExit(main())
