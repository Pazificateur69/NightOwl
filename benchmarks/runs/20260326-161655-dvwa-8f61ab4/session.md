# Benchmark Session

## Session Info

- Date: 2026-03-26
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes

## Target

- Target: dvwa
- URL: http://127.0.0.1:8081

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

- Command: `.venv/bin/python -m nightowl.cli.main scan web http://127.0.0.1:8081 --core`
- Start: 2026-03-26T16:16:55.841119+00:00
- End: 2026-03-26T16:17:01.629311+00:00
- Duration: 5.79s
- Return code: 0
- Findings count: 11
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260326-161655-dvwa-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260326-161655-dvwa-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260326-161655-dvwa-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-26-dvwa-8f61ab4.md`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
