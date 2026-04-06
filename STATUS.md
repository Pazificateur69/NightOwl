# NightOwl Status

## Current Phase

NightOwl is being transitioned from a broad experimental pentest framework into a smaller, more serious and recommendable tool with a documented core.

## Roadmap Progress

### Week 1: Stabilize the Core

Status: `in_progress`

Completed:

- added `finding_state` to findings
- added `confidence_score` to findings
- added module maturity classification:
  - `recommended`
  - `usable-with-caution`
  - `experimental`
- defined official core modules in code
- enriched findings automatically with module maturity metadata
- exposed state/confidence in HTML and Markdown reports
- exposed state/confidence in persisted findings returned by the DB layer

Remaining:

- unify proxy/rate-limit/timeouts more deeply across non-core modules
- expand README/module docs around maturity levels

### Week 2: Harden the Core Modules

Status: `in_progress`

Completed:

- improved `header-analyzer` to avoid flagging missing HSTS on plain HTTP
- improved `cors-checker` to reduce noisy arbitrary-origin findings
- tightened `cors-checker` so permissive preflight methods alone no longer count as a finding without already-demonstrated broad origin exposure
- improved `ssl-analyzer` protocol weakness detection and finding confidence/state
- improved `dir-bruteforce` with soft-404 filtering logic
- improved `sqli-scanner` timing heuristics and finding state/confidence
- improved `port-scanner` finding state/confidence consistency
- improved `xss-scanner` response classification and finding confidence/state
- improved `deep-port-scan` finding confidence/state and service classification
- unified shared HTTP settings across core web modules through the plugin base
- added focused unit tests for hardened core-module helpers

Remaining focus:

- `header-analyzer`
- `xss-scanner`
- `sqli-scanner`
- `cors-checker`
- `ssl-analyzer`
- `port-scanner`
- `deep-port-scan`
- `dir-bruteforce`

### Week 3: Add Real Proof

Status: `in_progress`

Started:

- added a local benchmark workflow in `benchmarks/`
- added benchmark result templates for reproducible evidence capture
- added Docker benchmark targets for DVWA, Juice Shop, and WebGoat
- added `make bench-up`, `make bench-status`, and `make bench-down`
- added benchmark session files for DVWA, Juice Shop, and WebGoat
- added an automated benchmark runner that records raw outputs and session metadata
- added benchmark preflight checks and session snapshots for unreachable-lab visibility
- added benchmark summary tooling and clearer Makefile behavior when Docker is missing
- expanded benchmark profiles beyond the root page and added a `bench-run-all` workflow
- exposed maturity/core status in the CLI plugin inventory
- exposed core modules and maturity counts in the dashboard
- aligned the README positioning with the current proof level
- added API and dashboard integration tests
- fixed the dashboard/template rendering path for the current FastAPI/Starlette stack
- added raw vs deduplicated benchmark summary views
- added benchmark review documents for DVWA, Juice Shop, and WebGoat
- preserved a plausible Juice Shop SQLi signal as a concrete review target
- added first benchmark verdict classification layer with expected, confirmed, missed, and inconclusive outcomes
- added first explicit `likely_false_positive` rules for deprecated headers and generic public path discovery
- taught `dir-bruteforce` to classify public, interesting, and sensitive discoveries directly in the module
- added first content-aware refinement for `dir-bruteforce` using content-type, redirect target, and response preview
- added a dedicated `nightowl-lab` Docker target for XSS and SQLi calibration
- added route-level `quiet_expected` and `quiet_violation` benchmark verdicts for safe-context lab probes
- added authenticated benchmark bootstrap for DVWA and WebGoat, including DVWA setup reset and disposable WebGoat user creation
- fixed JSON-escaped reflection matching in `xss-scanner`, so WebGoat lesson output rendered from JSON now produces a benchmarked XSS hit instead of a silent miss
- taught `sqli-scanner` to extract and submit simple HTML forms, which turns WebGoat `SqlInjection.lesson` from a dead template into a benchmarked SQLi source
- made benchmark SQLi families action-aware, so WebGoat SQLi evidence is attributed to specific lesson actions instead of being collapsed by title alone

Planned focus:

- lab-based benchmarks
- reproducible vulnerable targets
- detection/fp/fn measurements
- module maturity review based on evidence

### Week 4: Ship a Serious Product

Status: `not_started`

Planned focus:

- release hardening
- docs and usage guidance
- benchmark publication
- clearer public positioning

## Current Core Modules

- `header-analyzer`
- `xss-scanner`
- `sqli-scanner`
- `cors-checker`
- `ssl-analyzer`
- `port-scanner`
- `deep-port-scan`
- `dir-bruteforce`

## Current Risks

- test suite currently covers unit paths well, but benchmark and end-to-end coverage remain limited
- module quality remains uneven outside the core path
- maturity labels are currently policy-driven, not yet benchmark-driven
- benchmark signal is cleaner than before, but `header-analyzer` still dominates raw counts on the HTTP labs
- benchmark verdicts are now present, but they still rely on manually curated profile expectations
- likely false positive coverage is still intentionally narrow and rule-based
- `dir-bruteforce` is now lightly content-aware, but still lacks deeper body analysis and authenticated verification
- the new `nightowl-lab` target still needs benchmark execution and review before it can influence maturity labels
- `nightowl-lab` now runs successfully, but its header signal still dominates the raw count and should be treated carefully
- authenticated benchmark coverage is now meaningful for one WebGoat SQLi lesson page and one WebGoat XSS lesson action, but broader lesson coverage is still limited

## Last Update

- implemented finding state/confidence plumbing
- implemented initial module maturity/core classification
- updated reports and dashboard-facing finding payloads
- hardened `xss-scanner` and `deep-port-scan`
- started reproducible benchmark scaffolding
- exposed module maturity more clearly across CLI, dashboard, and README
- added CLI support for core-only scans and maturity-filtered plugin listings
- applied shared timeout/proxy/request-delay plumbing to core HTTP modules
- installed local dev/test dependencies and executed the unit suite successfully
- added web integration coverage and validated the full test suite locally
- added a repo-level TODO backlog tied to real benchmark evidence
- added benchmark reviews tied to current artifacts
- added raw vs family-deduplicated benchmark summary reporting
- classified the current Juice Shop SQLi hit as a reviewed benchmark `confirmed_hit`
- started marking benchmark noise explicitly instead of leaving all non-confirmed signal as inconclusive
- reduced `dir-bruteforce` severity inflation at the source for public and interesting paths
- started using response content to distinguish generic HTML discoverability from more suspicious structured exposure
- added the first repo-local XSS/SQLi benchmark lab and wired it into the benchmark runner
- exercised the local XSS/SQLi lab and confirmed one XSS plus two SQLi benchmark hits
- started tracking safe-context routes as explicit benchmark “quiet” expectations instead of leaving them only in review notes
- moved DVWA and WebGoat benchmark flows past the login wall so benchmark state no longer depends on manual lab preparation
- confirmed a real authenticated WebGoat XSS benchmark hit on `attack5a` and corrected its confidence so JSON-rendered lesson output no longer looks stronger than a confirmed HTML sink
- confirmed real authenticated WebGoat SQLi signal by extracting lesson forms and detecting error-based HSQLDB failures on POST actions
- promoted reviewed WebGoat SQLi families for assignment5b, attack8, attack9, and attack10 into confirmed benchmark signal with action-aware family tracking
- removed legacy `X-XSS-Protection` from the default `header-analyzer` signal and regenerated DVWA, Juice Shop, and WebGoat benchmarks on the cleaner baseline
- corrected the benchmark runner scope payload so it stores the real host/IP instead of the full target URL
- aligned the HTTP benchmark profiles with the explicit `ssl-analyzer` signal `No TLS — target uses plain HTTP`
- verified that Juice Shop no longer emits the old standalone `cors-checker` “dangerous methods” finding on the default benchmark profile
- validated the current repo state with `245 passed, 2 warnings`
