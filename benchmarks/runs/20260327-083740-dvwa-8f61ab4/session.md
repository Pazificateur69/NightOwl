# Benchmark Session

## Session Info

- Date: 2026-03-27
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes

## Target

- Target: dvwa
- Profile: Multi-probe benchmark for DVWA unauthenticated entrypoints.
- URL: http://127.0.0.1:8081
- Probes: 4

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

- `header-analyzer`
- `dir-bruteforce`

## Probe URLs

- `http://127.0.0.1:8081/`
- `http://127.0.0.1:8081/login.php`
- `http://127.0.0.1:8081/robots.txt`
- `http://127.0.0.1:8081/instructions.php`

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260327-083740-dvwa-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8081/ --core`
- Start: 2026-03-27T08:37:40.842656+00:00
- End: 2026-03-27T08:38:03.688489+00:00
- Duration: 22.85s
- Return code: 0
- Findings count: 29
- Scan ID: a3a9c88a-0d7a-4102-941f-1ab8a03807ca
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-27-dvwa-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/reports/nightowl-a3a9c88a-20260327-083803.md`
- HTML report: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/reports/nightowl-a3a9c88a-20260327-083803.html`
- Probe Results JSON: `benchmarks/runs/20260327-083740-dvwa-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
