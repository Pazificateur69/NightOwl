# Benchmark Session

## Session Info

- Date: 2026-03-27
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes

## Target

- Target: webgoat
- Profile: Multi-probe benchmark for WebGoat unauthenticated login routes.
- URL: http://127.0.0.1:8083/WebGoat
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

## Probe URLs

- `http://127.0.0.1:8083/WebGoat/`
- `http://127.0.0.1:8083/WebGoat/login`
- `http://127.0.0.1:8083/WebGoat/WebGoat/login`
- `http://127.0.0.1:8083/WebGoat/WebGoat/login?error=1`
- `http://127.0.0.1:8083/WebGoat/WebGoat/start.mvc`

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260327-093826-webgoat-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8083/WebGoat/ --core`
- Start: 2026-03-27T09:38:26.808777+00:00
- End: 2026-03-27T09:38:57.422935+00:00
- Duration: 30.61s
- Return code: 0
- Findings count: 31
- Scan ID: d1149412-fbab-4159-8b6a-6f189338ed3b
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-27-webgoat-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/reports/nightowl-d1149412-20260327-093857.md`
- HTML report: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/reports/nightowl-d1149412-20260327-093857.html`
- Probe Results JSON: `benchmarks/runs/20260327-093826-webgoat-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
