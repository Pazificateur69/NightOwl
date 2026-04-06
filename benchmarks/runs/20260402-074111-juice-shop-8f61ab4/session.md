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

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260402-074111-juice-shop-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8082/ --core`
- Start: 2026-04-02T07:41:11.421393+00:00
- End: 2026-04-02T07:41:48.838933+00:00
- Duration: 37.42s
- Return code: 0
- Findings count: 8
- Scan ID: 995ec04e-9afc-4c9e-8616-ea2aa4010167
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-04-02-juice-shop-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/reports/nightowl-995ec04e-20260402-074148.md`
- HTML report: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/reports/nightowl-995ec04e-20260402-074148.html`
- Probe Results JSON: `benchmarks/runs/20260402-074111-juice-shop-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
