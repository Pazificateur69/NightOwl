# Benchmark Session

## Session Info

- Date: 2026-03-26
- Commit: 8f61ab4
- Operator: pazent
- Environment: python=3.14.3, cwd=/Users/pazent/Desktop/NightOwl, dirty_worktree=True
- Status: passed
- Reachable: yes

## Target

- Target: juice-shop
- URL: http://127.0.0.1:8082

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

- Command: `.venv/bin/python -m nightowl.cli.main scan web http://127.0.0.1:8082 --core`
- Start: 2026-03-26T16:17:10.634665+00:00
- End: 2026-03-26T16:17:16.678696+00:00
- Duration: 6.04s
- Return code: 0
- Findings count: 7
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260326-161710-juice-shop-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260326-161710-juice-shop-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260326-161710-juice-shop-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-26-juice-shop-8f61ab4.md`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
