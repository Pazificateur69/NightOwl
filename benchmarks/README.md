# NightOwl Benchmarks

This directory defines the first reproducible benchmark workflow for the NightOwl core modules.

## Scope

The benchmark track is intentionally narrow:

- `header-analyzer`
- `xss-scanner`
- `sqli-scanner`
- `cors-checker`
- `ssl-analyzer`
- `port-scanner`
- `deep-port-scan`
- `dir-bruteforce`

The goal is not to claim parity with mature tools. The goal is to measure:

- detections that are correct
- obvious false positives
- obvious false negatives
- runtime per target

## Local Targets

The default local lab uses Docker services defined in [docker/docker-compose.yml](../docker/docker-compose.yml):

- DVWA: `http://127.0.0.1:8081`
- Juice Shop: `http://127.0.0.1:8082`
- WebGoat: `http://127.0.0.1:8083/WebGoat`
- NightOwl Lab: `http://127.0.0.1:8084`
- CORS Lab: `http://127.0.0.1:8085`

Bring the lab up with:

```bash
make bench-up
```

Check status with:

```bash
make bench-status
```

Run an automated benchmark session and capture raw artifacts with:

```bash
make bench-run-dvwa
make bench-run-juice-shop
make bench-run-webgoat
make bench-run-nightowl-lab
make bench-run-cors-lab
make bench-run-all
make bench-summary
```

Stop the lab with:

```bash
make bench-down
```

## Dedicated Calibration Lab

The `nightowl-lab` service lives under `benchmarks/labs/nightowl_lab/`.

It exists to exercise scanner behavior that the broader labs still do not prove cleanly:

- executable reflected XSS
- escaped XSS
- JSON reflection
- comment and attribute reflection
- error-based SQLi
- time-based SQLi

This target is for scanner calibration and regression testing. It is not meant to support inflated product claims.

## Suggested Runs

Run the core web scan against each target:

```bash
nightowl scan web http://127.0.0.1:8081 --all
nightowl scan web http://127.0.0.1:8082 --all
nightowl scan web http://127.0.0.1:8083/WebGoat --all
```

Run the network core where relevant:

```bash
nightowl scan network 127.0.0.1 --ports 1-10000 --vuln
```

## Result Format

Copy [results-template.md](./results-template.md) for each benchmark session.

Automated runs store raw outputs under `benchmarks/runs/<timestamp>-<target>-<commit>/`:

- `stdout.txt`
- `stderr.txt`
- `metadata.json`
- `session.md`

They also write a readable snapshot under `benchmarks/sessions/` with the date, target, and commit in the filename.

If the benchmark target is unreachable, the runner records a failed preflight explicitly instead of pretending the benchmark ran successfully.

Use `make bench-summary` to print the latest benchmark status by target from the stored metadata.

Each session should record:

- commit or tag tested
- target and target version
- modules executed
- expected vulnerable surfaces
- confirmed detections
- false positives
- missed detections
- noteworthy errors
- total runtime

## Rules

- Do not publish benchmark claims without keeping the raw notes in this directory.
- Do not mark a module as `recommended` from feature presence alone.
- If a module has repeated false positives on the local lab, downgrade its maturity.
