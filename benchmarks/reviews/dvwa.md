# DVWA Benchmark Review

## Latest Reviewed Run

- Session: [2026-03-26-dvwa-8f61ab4.md](/Users/pazent/Desktop/NightOwl/benchmarks/sessions/2026-03-26-dvwa-8f61ab4.md)
- Findings: [findings.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260327-103917-dvwa-8f61ab4/findings.json)
- Stats: [stats.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260327-103917-dvwa-8f61ab4/stats.json)
- Probe results: [probe-results.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260327-103917-dvwa-8f61ab4/probe-results.json)
- Verdicts: [verdicts.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260327-103917-dvwa-8f61ab4/verdicts.json)

## What Was Detected Correctly

- `header-analyzer` consistently found missing headers across the authenticated DVWA shell and lesson routes.
- `dir-bruteforce` discovered real reachable paths such as `/robots.txt`, `/.htaccess`, `/docs`, and `/config`.
- `xss-scanner` now produces the expected reflected-XSS hit on `/vulnerabilities/xss_r/?name=...`.
- `sqli-scanner` now produces the expected error-based SQLi hit on `/vulnerabilities/sqli/?id=...`.

## What Looks Noisy

- `header-analyzer` dominates the run mostly because the same header weaknesses repeat across multiple probes.
- `dir-bruteforce` currently treats benign discoverability like `robots.txt` as a medium signal, which is still too aggressive for default reporting.
- Missing `X-XSS-Protection` is now treated as a benchmark `likely_false_positive`, because that header is deprecated and too weak to count as a serious modern issue.

## What Was Missed Or Not Exercised

- `cors-checker` and `ssl-analyzer` were also not meaningfully exercised here.
- The benchmark is now authenticated and lesson-aware, so future misses from `xss-scanner` or `sqli-scanner` on these routes should be treated as real regressions.

## Engineering Follow-Up

- Deduplicate `header-analyzer` findings more aggressively in benchmark summary and reporting.
- Lower or better contextualize `dir-bruteforce` severity for low-risk files.
- Treat the DVWA auth bootstrap path as a regression target for benchmark config loading, because losing cookies silently erased both XSS and SQLi signal.
