# Juice Shop Benchmark Review

## Latest Reviewed Run

- Session: [2026-04-02-juice-shop-8f61ab4.md](/Users/pazent/Desktop/NightOwl/benchmarks/sessions/2026-04-02-juice-shop-8f61ab4.md)
- Findings: [findings.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260402-072953-juice-shop-8f61ab4/findings.json)
- Stats: [stats.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260402-072953-juice-shop-8f61ab4/stats.json)
- Probe results: [probe-results.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260402-072953-juice-shop-8f61ab4/probe-results.json)
- Verdicts: [verdicts.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260402-072953-juice-shop-8f61ab4/verdicts.json)

## What Was Detected Correctly

- `header-analyzer` found missing policy headers across multiple Juice Shop routes.
- `dir-bruteforce` found real exposed routes like `/robots.txt`, `/media`, and `/assets`.
- `sqli-scanner` produced one meaningful error-based hit on `/rest/products/search?q=...` with a `500` response and a SQLite error signature.
- That SQLi finding is now tracked as a reviewed `confirmed_hit` in the benchmark verdict layer.
- `ssl-analyzer` now reports the honest plain-HTTP signal `No TLS — target uses plain HTTP`, which is expected on this local deployment.

## What Looks Noisy

- `header-analyzer` still inflates raw counts across probes because the same missing headers repeat, even after removing legacy `X-XSS-Protection` from the default baseline.
- `dir-bruteforce` still mixes generic static discoverability with security-relevant files.
- Generic discoveries like `/assets` and `/media` should be treated as benchmark noise unless they expose sensitive content; they now fit the first `likely_false_positive` bucket.
- The old standalone CORS “dangerous methods” signal on this profile has been removed by requiring broader origin exposure first.

## What Was Missed Or Not Exercised

- `xss-scanner` remains unproven on this profile because the benchmark still relies on direct HTTP probes, not client-heavy browser flows.
- `cors-checker` remains unproven on this benchmark set.
- `ssl-analyzer` is now honest here, but still only exercised in the plain-HTTP case rather than against intentionally weak TLS.

## Engineering Follow-Up

- Preserve the Juice Shop SQLi artifact as a regression case and classify it formally.
- Add browser-driven or scripted Juice Shop routes to exercise XSS and more realistic search/login flows.
- Split `dir-bruteforce` findings into benign asset discovery vs sensitive discovery.
