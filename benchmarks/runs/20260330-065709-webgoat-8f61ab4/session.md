# Benchmark Session

## Session Info

- Date: 2026-03-30
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
- Probes: 6

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

## Probe URLs

- `http://127.0.0.1:8083/WebGoat/`
- `http://127.0.0.1:8083/WebGoat/welcome.mvc`
- `http://127.0.0.1:8083/WebGoat/start.mvc?lang=en`
- `http://127.0.0.1:8083/WebGoat/service/lessonmenu.mvc`
- `http://127.0.0.1:8083/WebGoat/SqlInjection.lesson`
- `http://127.0.0.1:8083/WebGoat/CrossSiteScripting.lesson`

## Auth Notes

- Created disposable WebGoat user nightowl-c6e9f5.
- Authenticated to WebGoat via http://127.0.0.1:8083/WebGoat/login.
- Lesson menu reached at http://127.0.0.1:8083/WebGoat/service/lessonmenu.mvc.
- Final login response landed at http://127.0.0.1:8083/WebGoat/start.mvc?username=nightowl-c6e9f5#lesson/WebGoatIntroduction.lesson.

## Execution

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260330-065709-webgoat-8f61ab4/probe-01/benchmark-config.yaml scan web http://127.0.0.1:8083/WebGoat/ --core`
- Start: 2026-03-30T06:57:09.964656+00:00
- End: 2026-03-30T06:57:47.715433+00:00
- Duration: 37.75s
- Return code: 0
- Findings count: 37
- Scan ID: 91d7ba94-1b12-402d-bd92-01b6ecd7c035
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-30-webgoat-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/stats.json`
- Verdicts JSON: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/verdicts.json`
- Markdown report: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/reports/nightowl-91d7ba94-20260330-065747.md`
- HTML report: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/reports/nightowl-91d7ba94-20260330-065747.html`
- Probe Results JSON: `benchmarks/runs/20260330-065709-webgoat-8f61ab4/probe-results.json`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
