# NightOwl TODO

## Goal

Turn NightOwl from a broad experimental framework into a serious pentest tool with:

- a reliable core
- benchmark-backed module maturity
- clearer signal vs noise
- stronger product behavior across CLI, API, reporting, and benchmarks

This TODO is intentionally implementation-oriented.
It should drive the next engineering work, not act as marketing copy.

## Current Evidence Snapshot

What recent benchmark runs show today:

- `header-analyzer` produces consistent signal across DVWA, Juice Shop, and WebGoat
- `dir-bruteforce` produces consistent signal across DVWA, Juice Shop, and WebGoat
- `sqli-scanner` produced at least one finding on the richer Juice Shop profile
- `sqli-scanner` now also produces real form-based WebGoat findings on authenticated lesson routes
- `xss-scanner` is now demonstrated on the dedicated NightOwl lab, DVWA, and authenticated WebGoat
- `cors-checker` and `ssl-analyzer` remain largely unproven in current lab profiles
- benchmark noise from legacy `X-XSS-Protection` and weak standalone CORS preflight heuristics has been reduced materially in the latest HTTP-lab runs
- multi-probe benchmark profiles are now working and reproducible

What this means:

- some modules are operationally demonstrated
- some modules are still only architecturally present
- the next work should prioritize header aggregation, CORS proof labs, and SSL proof quality, not module count

## Priority Order

1. Reduce benchmark ambiguity
2. Improve detection depth in the core modules
3. Make module maturity evidence-driven
4. Improve product quality and release readiness
5. Only then widen coverage

## Current Sprint

This is the execution backlog for the next short iteration.

1. `done` Tighten `dir-bruteforce` so public assets and generic HTML pages stop inflating signal.
2. `done` Add benchmark delta tracking so each target shows what changed vs the previous run.
3. `done` Expose benchmark delta and verdict summaries in the dashboard.
4. `done` Build a small local XSS/SQLi benchmark lab under `benchmarks/labs/`.
5. `done` Add authenticated benchmark flows for DVWA and WebGoat.
6. `done` Expand benchmark verdict rules beyond the current narrow false-positive set, especially for safe-context calibration routes.

## P0: Benchmark Truth

These are the highest-value tasks right now.

### P0.1 Benchmark Verdict Model

Implement benchmark verdict tracking per finding:

- `expected_hit`
- `confirmed_hit`
- `likely_false_positive`
- `missed_expected`
- `inconclusive`

Acceptance criteria:

- benchmark artifacts can store expected vs observed outcomes
- each benchmark profile can declare expected finding categories
- summary output shows hits, misses, and noise separately

Current progress:

- benchmark artifacts now include a first `verdicts.json`
- profiles can declare expected and reviewed-confirmed finding families
- summary now shows confirmed, expected, missed, and inconclusive counts
- likely false positive classification now covers a first narrow set of deprecated-header and generic-path cases
- the next step is to widen that coverage using benchmark reviews instead of ad hoc intuition

### P0.2 Per-Target Expected Outcomes

Add expected outcomes to benchmark profiles:

- expected headers
- expected discoverable paths
- expected vulnerable route classes
- known limitations for that profile

Acceptance criteria:

- each profile in `benchmarks/profiles.py` includes expected outcomes
- summary can compare observed findings to declared expectations

### P0.3 Benchmark Review Documents

Create benchmark review docs per target:

- DVWA review
- Juice Shop review
- WebGoat review

Each should contain:

- what was detected correctly
- what was noisy
- what was missed
- what must change in code

Acceptance criteria:

- one review file per target under `benchmarks/reviews/`
- findings linked to actual run artifacts

Current progress:

- initial review docs now exist for DVWA, Juice Shop, and WebGoat
- the next step is to upgrade them from qualitative notes to verdict-driven reviews

### P0.4 Custom Local Lab For XSS/SQLi

Create one small intentionally vulnerable local app focused on:

- reflected XSS
- reflected XSS in safe context
- SQLi error-based
- SQLi time-based

This is critical because current benchmark roots do not strongly exercise these scanners.

Acceptance criteria:

- custom lab added under `benchmarks/labs/`
- Dockerized or runnable locally
- routes documented and reproducible

## P1: Core Scanner Hardening

### P1.1 `sqli-scanner`

Tasks:

- add at least one second WebGoat XSS lesson action and review it
- add route-aware benchmark cases for true and false SQLi signals
- separate noisy time-based hints from higher-confidence DB error hits
- enrich evidence with baseline vs injected delta

Acceptance criteria:

- benchmark verdicts for at least 3 SQLi scenarios
- clearer separation between `confirmed` and `suspected`
- fewer blind high-severity reports without supporting evidence

### P1.2 `xss-scanner`

Tasks:

- add benchmark routes with:
  - executable reflection
  - encoded reflection
  - reflection inside JSON
  - reflection inside HTML comments
  - reflection inside inert attributes
- improve sink classification and confidence rules
- store a small context excerpt in evidence

Acceptance criteria:

- benchmarked on a dedicated XSS lab
- at least one true hit and multiple false-positive guards demonstrated

### P1.3 `dir-bruteforce`

Tasks:

- differentiate interesting paths from generic discoverability
- reduce severity inflation for benign files like `robots.txt`
- add optional allowlist/denylist of “interesting” sensitive paths

Acceptance criteria:

- `robots.txt` and generic static assets are lower-noise by default
- reporting distinguishes “discovered asset” vs “security-relevant file”

### P1.4 `header-analyzer`

Tasks:

- reduce duplicate header findings across multi-probe runs
- aggregate header weaknesses by application instead of repeating same headers per route
- distinguish route-specific vs global header issues
- keep legacy headers behind an explicit opt-in mode instead of the default serious baseline

Acceptance criteria:

- benchmark summary no longer inflates `header-analyzer` counts only because multiple probes share the same headers
- reports can show both raw and deduplicated views
- deprecated headers like `X-XSS-Protection` are absent from the default benchmark baseline unless legacy mode is explicitly enabled

### P1.5 `cors-checker`

Tasks:

- add a custom benchmark target with intentional CORS misconfigs
- test wildcard, credential reflection, null origin, and allowlist behavior
- improve output to show request origin and actual ACAO/ACAC values clearly
- keep “dangerous methods” gated behind demonstrated broad-origin exposure so standalone preflight noise stays out of the default signal

Acceptance criteria:

- at least 4 benchmarked CORS scenarios
- clear evidence for real misconfigs

### P1.6 `ssl-analyzer`

Tasks:

- benchmark against a controlled weak-TLS target or fixture
- verify behavior on plain HTTP targets is explicit and not misleading
- make “not applicable” vs “clean” distinction visible

Acceptance criteria:

- benchmarked on both HTTP and HTTPS fixtures
- no ambiguous silent behavior on non-TLS targets

## P2: Benchmark System Improvements

### P2.1 Deduplicated Summary Modes

Add two benchmark views:

- raw findings
- deduplicated findings by module/title/evidence family

Acceptance criteria:

- summary can display both counts
- multi-probe inflation becomes visible instead of hidden

Current progress:

- `benchmarks.summary` now shows raw findings and deduplicated finding-family counts
- the next step is to expose the same split in exported reports and dashboard views

### P2.2 Benchmark Delta Tracking

Track benchmark changes over time:

- findings count changed
- module signal changed
- new hits
- new misses
- new likely false positives

Acceptance criteria:

- compare latest run to previous run by target
- output a human-readable delta summary

### P2.3 Benchmark Health Gate

Add a lightweight gate:

- benchmark profile must be reachable
- run must complete
- artifacts must exist
- findings JSON must parse

Acceptance criteria:

- `bench-run-all` exits with a useful summary and non-zero status if core benchmark generation is broken

### P2.4 Probe Metadata

Store more probe context:

- probe-specific timings
- probe-specific stats
- probe-specific module counts

Acceptance criteria:

- `probe-results.json` includes more than just return code and count

## P3: Product Quality

### P3.1 Maturity Reclassification

Stop leaving core maturity labels policy-driven.

Tasks:

- downgrade modules not yet benchmark-demonstrated
- upgrade only when evidence exists
- store rationale for maturity changes

Acceptance criteria:

- maturity labels can be traced to benchmark evidence
- README and CLI reflect that rationale

### P3.2 Dashboard Benchmark View

Add a benchmark page or section:

- latest benchmark runs
- signal per module
- coverage per target
- benchmark notes

Acceptance criteria:

- dashboard exposes benchmark state without reading files manually

### P3.3 Report Quality

Improve benchmark-exported reports:

- include benchmark profile name
- include probe URLs
- include module signal summary
- include deduped summary

Acceptance criteria:

- reports are useful for engineering review, not just end-user display

### P3.4 Cleaner README Positioning

README should be aligned with evidence.

Tasks:

- add benchmark section linked to real artifacts
- separate “demonstrated” from “implemented”
- stop implying broad coverage equals proven coverage

Acceptance criteria:

- top-level README claims are supportable from repo artifacts

## P4: Tests and CI

### P4.1 CI Benchmark Smoke

Add CI jobs for:

- unit tests
- integration tests
- benchmark runner smoke tests

Acceptance criteria:

- benchmark helpers and summary are exercised automatically

### P4.2 Module-Specific Regression Suites

Focus on:

- `header-analyzer`
- `dir-bruteforce`
- `sqli-scanner`
- `xss-scanner`

Acceptance criteria:

- each core module has targeted regression cases tied to benchmark learnings

### P4.3 End-to-End Benchmark Artifact Validation

Acceptance criteria:

- generated `metadata.json`, `findings.json`, `stats.json`, and reports are validated in tests

## P5: Strategic Expansion

Do not start this until P0-P3 are materially done.

### P5.1 Authenticated Benchmark Flows

Add support for:

- login steps
- cookie/session reuse
- authenticated probe sets

This is necessary for meaningful DVWA and WebGoat vulnerability coverage.

### P5.2 Browser-Driven Benchmarking

For client-heavy apps like Juice Shop:

- add browser-driven or script-assisted benchmark flows
- exercise routes that pure HTTP GET probes miss

### P5.3 New Core Candidates

Only after evidence exists:

- `api-scanner`
- `tech-detect`
- `waf-detect`
- `dependency-confusion`

## Immediate Next 10 Tasks

1. Build a small local XSS/SQLi benchmark lab.
2. Expose benchmark summaries in the dashboard.
3. Reclassify module maturity from benchmark evidence.
4. Export deduplicated and verdict-aware benchmark signal into HTML/Markdown reports.
5. Add route-level coverage notes to benchmark summary output.
6. Add authenticated probe support for DVWA and WebGoat.
7. Add browser-driven benchmark support for Juice Shop.
8. Tie benchmark verdicts to release gating for core modules.
9. Broaden `likely_false_positive` rules from benchmark review evidence.
10. Make `dir-bruteforce` content-aware enough to distinguish structured secret exposure, generic HTML, and redirect-only noise more reliably.

## Anti-Goals

Do not spend the next phase on:

- adding more modules just to increase the count
- broadening README claims before evidence improves
- polishing visuals before benchmark truth gets better
- treating silence on an unexercised route as proof of failure

## Definition Of “Serious Tool”

NightOwl becomes a serious tool when:

- the benchmark artifacts are reproducible
- the core modules have measured behavior
- false positives and misses are documented
- module maturity is evidence-based
- claims in the docs match what the code actually proves
