# Benchmark Session

## Session Info

- Date: 2026-03-27
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes

## Target

- Target: nightowl-lab
- Profile: Dedicated local benchmark lab for reflected XSS and SQL injection routes.
- URL: http://127.0.0.1:8084
- Probes: 9

## Modules Run

- `header-analyzer`
- `xss-scanner`
- `sqli-scanner`
- `cors-checker`
- `ssl-analyzer`
- `port-scanner`
- `deep-port-scan`
- `dir-bruteforce`

## Expected Core Signal

- `xss-scanner`
- `sqli-scanner`
- `dir-bruteforce`

## Probe URLs

- `http://127.0.0.1:8084/`
- `http://127.0.0.1:8084/robots.txt`
- `http://127.0.0.1:8084/xss/reflected?q=hello`
- `http://127.0.0.1:8084/xss/escaped?q=hello`
- `http://127.0.0.1:8084/xss/json?q=hello`
- `http://127.0.0.1:8084/xss/comment?q=hello`
- `http://127.0.0.1:8084/xss/attr?q=hello`
- `http://127.0.0.1:8084/sql/error?q=apple`
- `http://127.0.0.1:8084/sql/time?q=apple`

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8084/ --core`
- Start: 2026-03-27T10:20:30.264585+00:00
- End: 2026-03-27T10:21:37.290297+00:00
- Duration: 67.03s
- Return code: 0
- Findings count: 59
- Scan ID: 2acdb29c-981c-43d1-9cf2-c5708e95f959
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-27-nightowl-lab-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/reports/nightowl-2acdb29c-20260327-102137.md`
- HTML report: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/reports/nightowl-2acdb29c-20260327-102137.html`
- Probe Results JSON: `benchmarks/runs/20260327-102030-nightowl-lab-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
