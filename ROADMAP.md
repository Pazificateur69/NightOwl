# NightOwl Roadmap

## Goal

Make NightOwl a serious, recommendable security tool by prioritizing reliability, evidence, and product quality over raw module count.

## Guiding Principle

NightOwl should not compete by saying "we have more modules".
It should compete by proving that a smaller core is trustworthy, tested, and useful.

Before adding new modules, improve confidence in the existing ones.

## Success Criteria

By the end of this roadmap, NightOwl should be able to credibly claim:

- a small set of tested and documented core modules
- reproducible benchmark results on known labs
- clear separation between stable, beta, and experimental features
- consistent behavior across CLI, API, reporting, and config
- meaningful evidence and confidence scoring for findings

## 4-Week Plan

### Week 1: Stabilize the Core

Focus on architectural consistency and trust signals.

Tasks:

- freeze the "official core" to 5-8 modules
- define finding states:
  - `confirmed`
  - `suspected`
  - `info`
- add a `confidence_score` field to findings
- standardize scope enforcement, timeouts, proxy handling, and rate limiting
- align config behavior across CLI, API, pipeline, and modules
- clean up README claims to distinguish:
  - `stable`
  - `beta`
  - `experimental`
- set up a minimal CI pipeline:
  - compile
  - lint
  - unit tests

Deliverables:

- documented core module set
- shared finding classification model
- consistent config and execution behavior
- more honest and maintainable README

### Week 2: Harden the Core Modules

Focus on a narrow set of modules and make them genuinely reliable.

Recommended core set:

- `header-analyzer`
- `xss-scanner`
- `sqli-scanner`
- `cors-checker`
- `ssl-analyzer`
- `port-scanner`
- `deep-port-scan`
- `dir-bruteforce`

Tasks:

- write strong unit tests for each core module
- add reproducible local test targets for each module
- reduce false positives
- improve evidence quality
- improve remediation quality
- document known limitations per module

Deliverables:

- high-value test coverage for the core
- reproducible local validation targets
- improved findings with better signal quality

### Week 3: Add Real Proof

Focus on proving effectiveness in a public, reproducible way.

Target labs:

- DVWA
- Juice Shop
- WebGoat
- one custom local app for targeted XSS/SQLi scenarios

Tasks:

- benchmark the core modules against known vulnerable targets
- measure:
  - successful detections
  - false positives
  - execution time
- publish a benchmark table per module
- classify all modules into:
  - `recommended`
  - `usable with caution`
  - `experimental`

Deliverables:

- benchmark results
- module quality classification
- public evidence that the core works on known labs

### Week 4: Ship a Serious Product

Focus on usability, release quality, and positioning.

Tasks:

- improve CLI/API/reporting consistency
- expose scan errors clearly in reports and dashboard
- display confidence and validation state in findings
- tag a proper release
- write:
  - installation guide
  - usage guide
  - limitations guide
  - comparison guide explaining when to use NightOwl vs Burp, ZAP, or Nuclei

Deliverables:

- release-ready version
- cleaner docs
- clearer user expectations
- stronger public positioning

## Product Rules

These rules should apply going forward.

### Rule 1: No New Module Without Quality Work

Before adding a new module, at least one existing module should gain:

- tests
- benchmark coverage
- documentation
- confidence scoring
- stable behavior

### Rule 2: Reliability Over Breadth

Prefer a smaller number of recommendable modules over a large number of shallow ones.

### Rule 3: Honest Positioning

NightOwl should be presented as:

- an open-source pentest automation framework
- under active development
- with a tested core and experimental extended modules
- useful for labs, research, pre-audit workflows, and learning
- complementary to mature tools such as Burp, ZAP, and Nuclei

It should not be positioned as a full replacement for established professional tooling until benchmark and detection quality justify that claim.

## Immediate Priorities

If work must be prioritized aggressively, do these first:

1. make the core modules reliable
2. improve test coverage
3. publish honest benchmark results
4. classify module maturity
5. refine documentation and release quality

## End State

NightOwl becomes a serious tool when users can say:

- the core works
- the results are understandable
- the limitations are clear
- the project is honest about what is mature and what is not
- the evidence matches the claims
