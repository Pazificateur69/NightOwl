# Benchmark Session

## Session Info

- Date: 2026-04-02
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes
- Auth Mode: dvwa-default-admin

## Target

- Target: dvwa
- Profile: Authenticated multi-probe benchmark for DVWA with setup bootstrap and targeted XSS/SQLi routes.
- URL: http://127.0.0.1:8081
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
- `xss-scanner`
- `sqli-scanner`
- `ssl-analyzer`

## Probe URLs

- `http://127.0.0.1:8081/`
- `http://127.0.0.1:8081/instructions.php`
- `http://127.0.0.1:8081/vulnerabilities/xss_r/?name=test`
- `http://127.0.0.1:8081/vulnerabilities/sqli/?id=1&Submit=Submit`
- `http://127.0.0.1:8081/robots.txt`

## Auth Notes

- Bootstrapped DVWA setup via http://127.0.0.1:8081/setup.php.
- Authenticated to DVWA as admin via http://127.0.0.1:8081/login.php.
- Post-login shell reached at http://127.0.0.1:8081/index.php.
- Final login response landed at http://127.0.0.1:8081/index.php.

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260402-074111-dvwa-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8081/ --core`
- Start: 2026-04-02T07:41:11.530382+00:00
- End: 2026-04-02T07:41:51.879345+00:00
- Duration: 40.35s
- Return code: 0
- Findings count: 15
- Scan ID: a8cf3a13-6fec-43a9-9301-1d54d9a514ce
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-04-02-dvwa-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/reports/nightowl-a8cf3a13-20260402-074151.md`
- HTML report: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/reports/nightowl-a8cf3a13-20260402-074151.html`
- Probe Results JSON: `benchmarks/runs/20260402-074111-dvwa-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
