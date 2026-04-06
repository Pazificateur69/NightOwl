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

- Target: juice-shop
- Profile: Multi-probe benchmark for Juice Shop unauthenticated frontend routes.
- URL: http://127.0.0.1:8082
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

- `header-analyzer`
- `dir-bruteforce`
- `sqli-scanner`
- `ssl-analyzer`

## Probe URLs

- `http://127.0.0.1:8082/`
- `http://127.0.0.1:8082/robots.txt`
- `http://127.0.0.1:8082/assets/public/images/uploads/`
- `http://127.0.0.1:8082/rest/products/search?q=apple`
- `http://127.0.0.1:8082/api/Challenges/?page=1`

## Auth Notes

- none

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260402-072953-juice-shop-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8082/ --core`
- Start: 2026-04-02T07:29:53.175944+00:00
- End: 2026-04-02T07:30:31.520359+00:00
- Duration: 38.34s
- Return code: 0
- Findings count: 20
- Scan ID: 7fb8d548-16d3-4e46-b48b-80227840ea08
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-04-02-juice-shop-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/reports/nightowl-7fb8d548-20260402-073031.md`
- HTML report: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/reports/nightowl-7fb8d548-20260402-073031.html`
- Probe Results JSON: `benchmarks/runs/20260402-072953-juice-shop-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
