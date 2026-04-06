# NightOwl Lab Benchmark Review

## Latest Reviewed Run

- Session: [2026-03-27-nightowl-lab-8f61ab4.md](/Users/pazent/Desktop/NightOwl/benchmarks/sessions/2026-03-27-nightowl-lab-8f61ab4.md)
- Findings: [findings.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/findings.json)
- Stats: [stats.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/stats.json)
- Verdicts: [verdicts.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/verdicts.json)

## What Was Detected Correctly

- `xss-scanner` produced a confirmed reflected-XSS hit on `/xss/reflected?q=...`.
- `sqli-scanner` produced both the reviewed error-based hit and the reviewed time-based blind hit on the dedicated SQL routes.
- `dir-bruteforce` still found `/robots.txt`, which is expected for this synthetic target.

## What Was Noisy

- `header-analyzer` still dominates the raw count because the lab intentionally does not ship hardened headers.
- The first run surfaced a real integration bug in `dir-bruteforce`: it bruteforced on top of query-string probes and inflated noise badly.
- After fixing URL normalization, the lab dropped from `263` findings to `59`, with `dir-bruteforce` falling from `205` findings to `1`.

## What Was Missed Or Stayed Quiet

- The safe-context XSS routes (`escaped`, `json`, `comment`, `attr`) stayed quiet, which is the intended outcome.
- Verdict coverage now records that explicitly as `quiet_expected=4` and `quiet_violation=0`, instead of leaving it only as a review note.
- `cors-checker` and `ssl-analyzer` are not exercised by this target.

## Engineering Follow-Up

- Use this lab as the regression target for `xss-scanner` and `sqli-scanner`.
- Keep the safe-context verdict rules tied to these exact routes so future XSS changes cannot silently regress.
- Consider reducing header-analyzer weight or excluding it on calibration-only targets where headers are not the point of the exercise.
