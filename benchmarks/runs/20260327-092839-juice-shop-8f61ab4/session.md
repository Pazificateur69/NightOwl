# Benchmark Session

## Session Info

- Date: 2026-03-27
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes

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

## Probe URLs

- `http://127.0.0.1:8082/`
- `http://127.0.0.1:8082/robots.txt`
- `http://127.0.0.1:8082/assets/public/images/uploads/`
- `http://127.0.0.1:8082/rest/products/search?q=apple`
- `http://127.0.0.1:8082/api/Challenges/?page=1`

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260327-092839-juice-shop-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8082/ --core`
- Start: 2026-03-27T09:28:39.561471+00:00
- End: 2026-03-27T09:29:13.888892+00:00
- Duration: 34.33s
- Return code: 0
- Findings count: 24
- Scan ID: b7e9daa1-24d5-4b6f-8229-174c8b078446
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-27-juice-shop-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/reports/nightowl-b7e9daa1-20260327-092913.md`
- HTML report: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/reports/nightowl-b7e9daa1-20260327-092913.html`
- Probe Results JSON: `benchmarks/runs/20260327-092839-juice-shop-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
