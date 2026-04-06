"""Summarize benchmark artifacts produced by the local runner."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from benchmarks.profiles import DEFAULT_CORE_MODULES, get_profile

DEFAULT_OUTPUT_DIR = Path("benchmarks/runs")


def load_results(output_dir: Path = DEFAULT_OUTPUT_DIR) -> list[dict]:
    results = []
    if not output_dir.exists():
        return results
    for metadata_path in sorted(output_dir.glob("*/metadata.json")):
        try:
            results.append(json.loads(metadata_path.read_text()))
        except Exception:
            continue
    return results


def latest_results_by_target(results: list[dict]) -> list[dict]:
    latest: dict[str, dict] = {}
    for result in results:
        target = result.get("target_name", "unknown")
        started_at = result.get("started_at", "")
        if target not in latest or started_at > latest[target].get("started_at", ""):
            latest[target] = result
    return [latest[name] for name in sorted(latest)]


def latest_and_previous_results_by_target(results: list[dict]) -> dict[str, dict[str, dict | None]]:
    grouped: dict[str, list[dict]] = {}
    for result in results:
        grouped.setdefault(result.get("target_name", "unknown"), []).append(result)

    output: dict[str, dict[str, dict | None]] = {}
    for target, target_results in grouped.items():
        ordered = sorted(target_results, key=lambda item: item.get("started_at", ""), reverse=True)
        output[target] = {
            "latest": ordered[0] if ordered else None,
            "previous": ordered[1] if len(ordered) > 1 else None,
        }
    return output


def load_findings_for_result(result: dict) -> list[dict]:
    findings_path = result.get("findings_json_path")
    if not findings_path:
        return []
    path = Path(findings_path)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def load_focus_findings_for_result(result: dict) -> list[dict]:
    findings_path = result.get("focus_findings_json_path")
    if not findings_path:
        return []
    path = Path(findings_path)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def load_verdicts_for_result(result: dict) -> dict:
    verdicts_path = result.get("verdicts_json_path")
    if not verdicts_path:
        return {}
    path = Path(verdicts_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _normalize_url_text(value: str) -> str:
    return re.sub(r"https?://[^\s]+", "<url>", value)


def finding_family(finding: dict) -> str:
    module_name = finding.get("module_name", "unknown")
    title = finding.get("title", "").strip()
    evidence = finding.get("evidence", "").strip()
    metadata = finding.get("metadata", {})

    if module_name == "header-analyzer" and title.startswith("Missing Security Header: "):
        header_name = title.split(":", 1)[1].strip()
        return f"{module_name}:missing-header:{header_name}"

    if module_name == "dir-bruteforce" and title.startswith("Discovered: "):
        match = re.match(r"Discovered:\s+([^\s]+)", title)
        if match:
            return f"{module_name}:discovered-path:{match.group(1)}"

    if module_name == "sqli-scanner":
        technique = metadata.get("technique", "").strip()
        action_url = metadata.get("action_url", "").strip()
        param = metadata.get("param", "").strip()
        if technique and action_url and param:
            action_path = urlparse(action_url).path.rsplit("/", 1)[-1]
            return f"{module_name}:{technique}:{action_path}:{param}"

    if module_name == "cors-checker":
        probe_url = metadata.get("benchmark_probe_url", "").strip()
        probe_path = urlparse(probe_url).path or "/"
        if title == "CORS: Wildcard with credentials":
            return f"{module_name}:wildcard-credentials:{probe_path}"
        if title == "CORS reflects arbitrary origins":
            return f"{module_name}:reflects-arbitrary-origins:{probe_path}"
        if title == "CORS allows null origin":
            return f"{module_name}:null-origin:{probe_path}"
        if title.startswith("CORS allows dangerous methods:"):
            return f"{module_name}:dangerous-methods:{probe_path}"

    if title:
        return f"{module_name}:{_normalize_url_text(title)}"

    first_line = evidence.splitlines()[0] if evidence else "unknown"
    return f"{module_name}:{_normalize_url_text(first_line)}"


def module_counts(findings: list[dict], *, dedupe_by: str | None = None) -> dict[str, int]:
    counts: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        module_name = finding.get("module_name", "unknown")
        if dedupe_by == "title":
            key = (module_name, finding.get("title", ""))
            if key in seen:
                continue
            seen.add(key)
        elif dedupe_by == "family":
            key = (module_name, finding_family(finding))
            if key in seen:
                continue
            seen.add(key)
        counts[module_name] = counts.get(module_name, 0) + 1
    return counts


def split_focus_module_counts(
    findings: list[dict],
    profile_name: str,
    *,
    dedupe_by: str = "family",
) -> tuple[dict[str, int], dict[str, int]]:
    profile = get_profile(profile_name)
    if not profile:
        return {}, module_counts(findings, dedupe_by=dedupe_by)

    expected_modules = set(profile.expected_modules)
    counts = module_counts(findings, dedupe_by=dedupe_by)
    focus = {name: count for name, count in counts.items() if name in expected_modules}
    background = {name: count for name, count in counts.items() if name not in expected_modules}
    return focus, background


def observation_lines(result: dict, findings: list[dict]) -> list[str]:
    counts = module_counts(findings)
    deduped_counts = module_counts(findings, dedupe_by="family")
    profile = get_profile(result.get("target_name", ""))
    focus_counts, background_counts = split_focus_module_counts(
        findings,
        result.get("target_name", ""),
        dedupe_by="family",
    )
    expected = set(profile.expected_modules if profile else ())
    covered_expected = sorted(name for name in expected if counts.get(name, 0) > 0)
    missed_expected = sorted(name for name in expected if counts.get(name, 0) == 0)
    unexercised = sorted(name for name in DEFAULT_CORE_MODULES if name not in expected)
    lines = []
    if counts:
        noisy_module = max(counts.items(), key=lambda item: item[1])
        lines.append(
            f"- `{result.get('target_name', 'unknown')}`: strongest signal came from `{noisy_module[0]}` with {noisy_module[1]} findings."
        )
    if deduped_counts:
        deduped_noisy_module = max(deduped_counts.items(), key=lambda item: item[1])
        lines.append(
            f"- `{result.get('target_name', 'unknown')}`: deduplicated signal still centers on `{deduped_noisy_module[0]}` with {deduped_noisy_module[1]} finding families."
        )
    if focus_counts:
        focus_module = max(focus_counts.items(), key=lambda item: item[1])
        lines.append(
            f"- `{result.get('target_name', 'unknown')}`: focus-profile signal centers on `{focus_module[0]}` with {focus_module[1]} finding families."
        )
    if background_counts:
        background_module = max(background_counts.items(), key=lambda item: item[1])
        lines.append(
            f"- `{result.get('target_name', 'unknown')}`: background signal is led by `{background_module[0]}` with {background_module[1]} finding families."
        )
    if counts and deduped_counts:
        raw_total = sum(counts.values())
        deduped_total = sum(deduped_counts.values())
        if raw_total > deduped_total:
            lines.append(
                f"- `{result.get('target_name', 'unknown')}`: multi-probe inflation reduced from {raw_total} raw findings to {deduped_total} finding families."
            )
    if covered_expected:
        lines.append(
            f"- `{result.get('target_name', 'unknown')}`: covered expected modules {', '.join(f'`{name}`' for name in covered_expected)}."
        )
    if missed_expected:
        lines.append(
            f"- `{result.get('target_name', 'unknown')}`: expected signal was missing for {', '.join(f'`{name}`' for name in missed_expected)}."
        )
    if unexercised:
        lines.append(
            f"- `{result.get('target_name', 'unknown')}`: unexercised on this profile {', '.join(f'`{name}`' for name in unexercised)}."
        )
    if profile and profile.notes:
        for note in profile.notes:
            lines.append(f"- `{result.get('target_name', 'unknown')}` note: {note}")
    return lines


def delta_lines(results: list[dict]) -> list[str]:
    lines: list[str] = []
    pairs = latest_and_previous_results_by_target(results)
    for target in sorted(pairs):
        latest = pairs[target]["latest"]
        previous = pairs[target]["previous"]
        if not latest or not previous:
            lines.append(f"- `{target}`: no previous run available for delta tracking yet.")
            continue

        latest_findings = latest.get("findings_count") or 0
        previous_findings = previous.get("findings_count") or 0
        finding_delta = latest_findings - previous_findings

        latest_verdicts = load_verdicts_for_result(latest).get("verdict_counts", {})
        previous_verdicts = load_verdicts_for_result(previous).get("verdict_counts", {})

        latest_modules = module_counts(load_findings_for_result(latest), dedupe_by="family")
        previous_modules = module_counts(load_findings_for_result(previous), dedupe_by="family")

        parts = [f"findings {finding_delta:+d} ({previous_findings} -> {latest_findings})"]
        for verdict_name in ("confirmed_hit", "missed_expected", "likely_false_positive"):
            latest_value = latest_verdicts.get(verdict_name, 0)
            previous_value = previous_verdicts.get(verdict_name, 0)
            delta = latest_value - previous_value
            if delta:
                parts.append(f"{verdict_name} {delta:+d} ({previous_value} -> {latest_value})")

        changed_modules = []
        for module_name in sorted(set(latest_modules) | set(previous_modules)):
            latest_value = latest_modules.get(module_name, 0)
            previous_value = previous_modules.get(module_name, 0)
            if latest_value != previous_value:
                changed_modules.append(f"`{module_name}` {previous_value}->{latest_value}")
        if changed_modules:
            parts.append("module signal " + ", ".join(changed_modules))

        lines.append(f"- `{target}`: " + "; ".join(parts))
    return lines


def render_markdown_summary(results: list[dict]) -> str:
    if not results:
        return "# Benchmark Summary\n\nNo benchmark artifacts found."

    lines = [
        "# Benchmark Summary",
        "",
        "| Target | Reachable | Return Code | Raw Findings | Deduped Families | Started | Artifact |",
        "|---|:---:|:---:|:---:|:---:|---|---|",
    ]
    latest = latest_results_by_target(results)
    for result in latest:
        findings = load_findings_for_result(result)
        raw_findings = result.get("findings_count")
        raw_findings_display = raw_findings if raw_findings is not None else "n/a"
        deduped_findings_display = len({finding_family(finding) for finding in findings}) if findings else "n/a"
        artifact = result.get("session_markdown_path", "")
        lines.append(
            "| {target} | {reachable} | {return_code} | {raw_findings} | {deduped_findings} | {started} | `{artifact}` |".format(
                target=result.get("target_name", "unknown"),
                reachable="yes" if result.get("reachable") else "no",
                return_code=result.get("return_code", "n/a"),
                raw_findings=raw_findings_display,
                deduped_findings=deduped_findings_display,
                started=result.get("started_at", "")[:19],
                artifact=artifact,
            )
        )

    lines.extend(["", "## Module Signal", ""])
    for result in latest:
        findings = load_findings_for_result(result)
        focus_findings = load_focus_findings_for_result(result)
        raw_counts = module_counts(findings)
        title_counts = module_counts(findings, dedupe_by="title")
        family_counts = module_counts(findings, dedupe_by="family")
        if focus_findings:
            focus_counts = module_counts(focus_findings, dedupe_by="family")
            background_counts = module_counts(
                [
                    finding
                    for finding in findings
                    if finding.get("module_name")
                    not in {item.get("module_name") for item in focus_findings}
                ],
                dedupe_by="family",
            )
        else:
            focus_counts, background_counts = split_focus_module_counts(
                findings,
                result.get("target_name", ""),
                dedupe_by="family",
            )
        if not raw_counts:
            lines.append(f"- `{result.get('target_name', 'unknown')}`: no detailed findings artifact available.")
            continue
        raw_summary = ", ".join(
            f"`{module}`={raw_counts[module]}"
            for module in sorted(raw_counts)
        )
        title_summary = ", ".join(
            f"`{module}`={title_counts[module]}"
            for module in sorted(title_counts)
        )
        family_summary = ", ".join(
            f"`{module}`={family_counts[module]}"
            for module in sorted(family_counts)
        )
        lines.append(f"- `{result.get('target_name', 'unknown')}` raw: {raw_summary}")
        lines.append(f"- `{result.get('target_name', 'unknown')}` dedup by title: {title_summary}")
        lines.append(f"- `{result.get('target_name', 'unknown')}` dedup by family: {family_summary}")
        if focus_counts:
            focus_summary = ", ".join(
                f"`{module}`={focus_counts[module]}"
                for module in sorted(focus_counts)
            )
            lines.append(f"- `{result.get('target_name', 'unknown')}` focus modules: {focus_summary}")
            if focus_findings:
                lines.append(
                    f"- `{result.get('target_name', 'unknown')}` focus artifact: `{result.get('focus_findings_json_path', '')}`"
                )
        if background_counts:
            background_summary = ", ".join(
                f"`{module}`={background_counts[module]}"
                for module in sorted(background_counts)
            )
            lines.append(f"- `{result.get('target_name', 'unknown')}` background modules: {background_summary}")

    lines.extend(["", "## Verdicts", ""])
    for result in latest:
        verdicts = load_verdicts_for_result(result)
        counts = verdicts.get("verdict_counts", {})
        if not counts:
            lines.append(f"- `{result.get('target_name', 'unknown')}`: no verdict artifact available.")
            continue
        count_summary = ", ".join(
            f"`{name}`={counts.get(name, 0)}"
            for name in (
                "confirmed_hit",
                "expected_hit",
                "quiet_expected",
                "quiet_violation",
                "missed_expected",
                "inconclusive",
                "likely_false_positive",
            )
        )
        lines.append(f"- `{result.get('target_name', 'unknown')}`: {count_summary}")
        missed = verdicts.get("missed_expected", [])
        if missed:
            missed_summary = ", ".join(f"`{item['family']}`" for item in missed)
            lines.append(f"- `{result.get('target_name', 'unknown')}` missed expected: {missed_summary}")
        quiet_violations = verdicts.get("quiet_violations", [])
        if quiet_violations:
            violation_summary = ", ".join(
                f"`{item['module_name']}` on `{item['probe_path']}`"
                for item in quiet_violations
            )
            lines.append(
                f"- `{result.get('target_name', 'unknown')}` quiet violations: {violation_summary}"
            )

    lines.extend(["", "## Deltas", ""])
    lines.extend(delta_lines(results))

    lines.extend(["", "## Observations", ""])
    for result in latest:
        findings = load_findings_for_result(result)
        lines.extend(observation_lines(result, findings))

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize benchmark runner artifacts.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Benchmark runs directory")
    args = parser.parse_args()

    results = load_results(Path(args.output_dir))
    print(render_markdown_summary(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
