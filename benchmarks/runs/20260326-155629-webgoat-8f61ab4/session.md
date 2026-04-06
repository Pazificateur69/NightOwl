# Benchmark Session

## Session Info

- Date: 2026-03-26
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: failed
- Reachable: no

## Target

- Target: webgoat
- URL: http://127.0.0.1:8083/WebGoat

## Modules Run

- `header-analyzer`
- `xss-scanner`
- `sqli-scanner`
- `cors-checker`
- `ssl-analyzer`
- `port-scanner`
- `deep-port-scan`
- `dir-bruteforce`

## Execution

- Command: `.venv/bin/nightowl scan web http://127.0.0.1:8083/WebGoat --core`
- Start: 2026-03-26T15:56:29.236085+00:00
- End: 2026-03-26T15:56:29.258548+00:00
- Duration: 0.02s
- Return code: 2
- Findings count: unparsed
- Preflight: [Errno 61] Connection refused

## Artifacts

- Raw stdout: `benchmarks/runs/20260326-155629-webgoat-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260326-155629-webgoat-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260326-155629-webgoat-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-26-webgoat-8f61ab4.md`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
