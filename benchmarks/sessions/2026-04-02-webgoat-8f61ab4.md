# Benchmark Session

## Session Info

- Date: 2026-04-02
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes
- Auth Mode: webgoat-disposable-user

## Target

- Target: webgoat
- Profile: Authenticated multi-probe benchmark for WebGoat shell routes and lesson menu access.
- URL: http://127.0.0.1:8083/WebGoat
- Probes: 7

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

- `http://127.0.0.1:8083/WebGoat/`
- `http://127.0.0.1:8083/WebGoat/welcome.mvc`
- `http://127.0.0.1:8083/WebGoat/start.mvc?lang=en`
- `http://127.0.0.1:8083/WebGoat/service/lessonmenu.mvc`
- `http://127.0.0.1:8083/WebGoat/SqlInjection.lesson`
- `http://127.0.0.1:8083/WebGoat/CrossSiteScripting.lesson`
- `http://127.0.0.1:8083/WebGoat/CrossSiteScripting/attack5a?QTY1=1&QTY2=1&QTY3=1&QTY4=1&field1=test&field2=111`

## Auth Notes

- Created disposable WebGoat user nightowl-bf21da.
- Authenticated to WebGoat via http://127.0.0.1:8083/WebGoat/login.
- Lesson menu reached at http://127.0.0.1:8083/WebGoat/service/lessonmenu.mvc.
- Final login response landed at http://127.0.0.1:8083/WebGoat/start.mvc?username=nightowl-bf21da#lesson/WebGoatIntroduction.lesson.

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260402-075128-webgoat-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8083/WebGoat/ --core`
- Start: 2026-04-02T07:51:28.808329+00:00
- End: 2026-04-02T07:53:10.782941+00:00
- Duration: 101.97s
- Return code: 0
- Findings count: 18
- Scan ID: 84bf2295-95e8-4c39-8878-f02d7cd6da9f
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-04-02-webgoat-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/reports/nightowl-84bf2295-20260402-075310.md`
- HTML report: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/reports/nightowl-84bf2295-20260402-075310.html`
- Probe Results JSON: `benchmarks/runs/20260402-075128-webgoat-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
