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

- Command: `.venv/bin/python -m nightowl.cli.main --config benchmarks/runs/20260326-161928-juice-shop-8f61ab4/benchmark-config.yaml scan web http://127.0.0.1:8082 --core`
- Start: 2026-03-26T16:19:28.722826+00:00
- End: 2026-03-26T16:19:34.646658+00:00
- Duration: 5.92s
- Return code: 0
- Findings count: 7
- Scan ID: cc053148-2eb0-4f5b-8d6b-4a825a2ff663
- Preflight: ok

## Artifacts

- Raw stdout: `benchmarks/runs/20260326-161928-juice-shop-8f61ab4/stdout.txt`
- Raw stderr: `benchmarks/runs/20260326-161928-juice-shop-8f61ab4/stderr.txt`
- Metadata JSON: `benchmarks/runs/20260326-161928-juice-shop-8f61ab4/metadata.json`
- Session Markdown: `benchmarks/sessions/2026-03-26-juice-shop-8f61ab4.md`
- Findings JSON: `benchmarks/runs/20260326-161928-juice-shop-8f61ab4/findings.json`
- Stats JSON: `benchmarks/runs/20260326-161928-juice-shop-8f61ab4/stats.json`
- Markdown report: `benchmarks/runs/20260326-161928-juice-shop-8f61ab4/reports/nightowl-cc053148-20260326-161934.md`
- HTML report: `benchmarks/runs/20260326-161928-juice-shop-8f61ab4/reports/nightowl-cc053148-20260326-161934.html`

## Notes

- Confirmed detections: pending review
- False positives: pending review
- Missed detections: pending review
- Follow-up fixes: pending review
