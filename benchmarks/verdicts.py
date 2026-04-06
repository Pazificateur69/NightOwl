"""Benchmark verdict classification helpers."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from benchmarks.profiles import BenchmarkProfile, QuietExpectation
from benchmarks.summary import finding_family


@dataclass(frozen=True)
class FindingVerdict:
    family: str
    verdict: str
    rationale: str
    module_name: str
    title: str


LIKELY_FALSE_POSITIVE_DIR_PATHS = {
    "/assets",
    "/docs",
    "/login",
    "/media",
}


def likely_false_positive_rationale(finding: dict, family: str) -> str | None:
    module_name = finding.get("module_name", "unknown")
    title = finding.get("title", "")

    if module_name == "header-analyzer" and title == "Missing Security Header: X-XSS-Protection":
        return (
            "X-XSS-Protection is deprecated in modern browsers, so treating its absence as a meaningful security weakness is often misleading."
        )

    if module_name == "dir-bruteforce":
        path = None
        if family.startswith("dir-bruteforce:discovered-path:"):
            path = family.split(":", 2)[2]
        if path in LIKELY_FALSE_POSITIVE_DIR_PATHS:
            return (
                f"The discovered path `{path}` is a common public route or static location, so surfacing it as a security finding is likely noisy."
            )

    return None


def _matching_quiet_expectation(
    profile: BenchmarkProfile | None, finding: dict
) -> QuietExpectation | None:
    if not profile:
        return None

    module_name = finding.get("module_name", "unknown")
    probe_url = (
        finding.get("metadata", {}).get("benchmark_probe_url")
        or finding.get("benchmark_probe_url")
        or ""
    )
    if not probe_url:
        return None

    probe_path = urlparse(probe_url).path
    for expectation in profile.expected_quiet_checks:
        if expectation.module_name == module_name and expectation.probe_path == probe_path:
            return expectation
    return None


def classify_finding(profile: BenchmarkProfile | None, finding: dict) -> FindingVerdict:
    family = finding_family(finding)
    module_name = finding.get("module_name", "unknown")
    title = finding.get("title", "")

    quiet_expectation = _matching_quiet_expectation(profile, finding)
    if quiet_expectation:
        return FindingVerdict(
            family=family,
            verdict="likely_false_positive",
            rationale=quiet_expectation.rationale,
            module_name=module_name,
            title=title,
        )

    if not profile:
        return FindingVerdict(
            family=family,
            verdict="inconclusive",
            rationale="No benchmark profile is available for this target.",
            module_name=module_name,
            title=title,
        )

    false_positive_rationale = likely_false_positive_rationale(finding, family)
    if false_positive_rationale:
        return FindingVerdict(
            family=family,
            verdict="likely_false_positive",
            rationale=false_positive_rationale,
            module_name=module_name,
            title=title,
        )

    if family in profile.reviewed_confirmed_families:
        return FindingVerdict(
            family=family,
            verdict="confirmed_hit",
            rationale="This finding family is explicitly reviewed and confirmed for the target profile.",
            module_name=module_name,
            title=title,
        )

    if family in profile.expected_finding_families:
        return FindingVerdict(
            family=family,
            verdict="expected_hit",
            rationale="This finding family is declared as expected signal for the benchmark profile.",
            module_name=module_name,
            title=title,
        )

    if module_name in profile.expected_modules:
        return FindingVerdict(
            family=family,
            verdict="inconclusive",
            rationale="The module is expected on this profile, but this exact finding family is not yet reviewed.",
            module_name=module_name,
            title=title,
        )

    return FindingVerdict(
        family=family,
        verdict="inconclusive",
        rationale="The module is not part of the expected signal for this benchmark profile.",
        module_name=module_name,
        title=title,
    )


def summarize_verdicts(profile: BenchmarkProfile | None, findings: list[dict]) -> dict:
    reviewed = [classify_finding(profile, finding) for finding in findings]
    verdict_counts = {
        "confirmed_hit": 0,
        "expected_hit": 0,
        "quiet_expected": 0,
        "quiet_violation": 0,
        "likely_false_positive": 0,
        "missed_expected": 0,
        "inconclusive": 0,
    }
    for item in reviewed:
        verdict_counts[item.verdict] += 1

    observed_families = {item.family for item in reviewed}
    missed_expected = []
    quiet_expected = []
    quiet_violations = []
    if profile:
        for family in profile.expected_finding_families:
            if family not in observed_families:
                missed_expected.append(
                    {
                        "family": family,
                        "verdict": "missed_expected",
                        "rationale": "This expected finding family was not observed in the benchmark run.",
                    }
                )
        verdict_counts["missed_expected"] = len(missed_expected)

        observed_quiet_hits: dict[tuple[str, str], list[str]] = {}
        for finding in findings:
            expectation = _matching_quiet_expectation(profile, finding)
            if not expectation:
                continue
            key = (expectation.module_name, expectation.probe_path)
            observed_quiet_hits.setdefault(key, []).append(finding_family(finding))

        for expectation in profile.expected_quiet_checks:
            key = (expectation.module_name, expectation.probe_path)
            observed_families_for_expectation = sorted(set(observed_quiet_hits.get(key, [])))
            if observed_families_for_expectation:
                quiet_violations.append(
                    {
                        "module_name": expectation.module_name,
                        "probe_path": expectation.probe_path,
                        "verdict": "quiet_violation",
                        "rationale": expectation.rationale,
                        "observed_families": observed_families_for_expectation,
                    }
                )
            else:
                quiet_expected.append(
                    {
                        "module_name": expectation.module_name,
                        "probe_path": expectation.probe_path,
                        "verdict": "quiet_expected",
                        "rationale": expectation.rationale,
                    }
                )
        verdict_counts["quiet_expected"] = len(quiet_expected)
        verdict_counts["quiet_violation"] = len(quiet_violations)

    return {
        "verdict_counts": verdict_counts,
        "findings": [
            {
                "family": item.family,
                "verdict": item.verdict,
                "rationale": item.rationale,
                "module_name": item.module_name,
                "title": item.title,
            }
            for item in reviewed
        ],
        "missed_expected": missed_expected,
        "quiet_expected": quiet_expected,
        "quiet_violations": quiet_violations,
    }
