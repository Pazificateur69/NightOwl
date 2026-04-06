# Benchmark Session

## Session Info

- Date: 2026-04-02
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes
- Auth Mode: none

## Target

- Target: cors-lab
- Profile: Dedicated local benchmark lab for CORS misconfiguration checks.
- URL: http://127.0.0.1:8085
- Probes: 5

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

- `cors-checker`

## Probe URLs

- `http://127.0.0.1:8085/wildcard-credentials`
- `http://127.0.0.1:8085/reflect-credentials`
- `http://127.0.0.1:8085/null-origin`
- `http://127.0.0.1:8085/dangerous-methods`
- `http://127.0.0.1:8085/allowlist`

## Auth Notes

- none

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260402-084644-cors-lab-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8085/wildcard-credentials --core`
- Start: 2026-04-02T08:46:44.994675+00:00
- End: 2026-04-02T08:47:16.520174+00:00
- Duration: 31.53s
- Return code: 0
- Findings count: 15
- Scan ID: 7dc1efd5-cf6a-436b-a8fe-e16858b553c3
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-04-02-cors-lab-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/verdicts.json`
- Focus Findings JSON: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/focus-findings.json`
- Focus Stats JSON: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/focus-stats.json`
- Markdown report: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/reports/nightowl-7dc1efd5-20260402-084716.md`
- HTML report: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/reports/nightowl-7dc1efd5-20260402-084716.html`
- Focus Markdown report: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/reports/nightowl-7dc1efd5-20260402-084716.md`
- Focus HTML report: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/reports/nightowl-7dc1efd5-20260402-084716.html`
- Probe Results JSON: `benchmarks/runs/20260402-084644-cors-lab-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
