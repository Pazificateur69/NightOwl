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

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260402-075637-cors-lab-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8085/wildcard-credentials --core`
- Start: 2026-04-02T07:56:37.251860+00:00
- End: 2026-04-02T07:57:08.293433+00:00
- Duration: 31.04s
- Return code: 0
- Findings count: 11
- Scan ID: 13e4e8ef-b17d-4c81-aa5f-733ba6852d79
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-04-02-cors-lab-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/reports/nightowl-13e4e8ef-20260402-075708.md`
- HTML report: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/reports/nightowl-13e4e8ef-20260402-075708.html`
- Probe Results JSON: `benchmarks/runs/20260402-075637-cors-lab-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
