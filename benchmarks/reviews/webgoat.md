# WebGoat Benchmark Review

## Latest Reviewed Run

- Session: [2026-04-02-webgoat-8f61ab4.md](/Users/pazent/Desktop/NightOwl/benchmarks/sessions/2026-04-02-webgoat-8f61ab4.md)
- Findings: [findings.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260402-073121-webgoat-8f61ab4/findings.json)
- Stats: [stats.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260402-073121-webgoat-8f61ab4/stats.json)
- Probe results: [probe-results.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260402-073121-webgoat-8f61ab4/probe-results.json)
- Verdicts: [verdicts.json](/Users/pazent/Desktop/NightOwl/benchmarks/runs/20260402-073121-webgoat-8f61ab4/verdicts.json)

## What Was Detected Correctly

- `header-analyzer` consistently found absent response headers on the authenticated WebGoat shell routes.
- `dir-bruteforce` produced at least one real path discovery.
- The benchmark now authenticates successfully with a disposable local user and reaches `/service/lessonmenu.mvc`.
- `xss-scanner` now detects the reflected lesson action on `/CrossSiteScripting/attack5a`, with the finding intentionally downgraded to `suspected` because the payload is rendered from a JSON output field rather than a plain HTML response.
- `sqli-scanner` now extracts simple lesson forms from `/SqlInjection.lesson` and submits them, producing reviewed confirmed HSQLDB error-based signal on:
  - `assignment5b:userid`
  - `attack8:name`
  - `attack8:auth_tan`
  - `attack9:name`
  - `attack9:auth_tan`
  - `attack10:action_string`
- `ssl-analyzer` now reports the correct plain-HTTP signal for this local deployment instead of the older noisy “TLS port 443 is not reachable” artifact.

## What Looks Noisy

- The run is still header-driven, so the raw findings count overstates real coverage, even after removing legacy `X-XSS-Protection` from the default header baseline.
- WebGoat route coverage is still shallow even after login, which makes repeated header findings look stronger than they are.
- Generic discovery of `/login` should not be treated as a meaningful security issue by default and belongs in the likely-noise bucket.
- The raw count is still inflated by repeated header findings across probes, even though the exploit-oriented signal is much better than before.

## What Was Missed Or Not Exercised

- `cors-checker` remains unproven on this profile.
- `ssl-analyzer` is now honest on this profile, but still only exercised in the plain-HTTP case rather than against intentionally weak TLS.
- `dir-bruteforce` still misses `/robots.txt` on this profile, which is the only remaining declared `missed_expected` family.
- Authentication is now benchmark-demonstrated, and both XSS and SQLi coverage are present, but exploit-oriented depth is still narrow compared with the full WebGoat lesson set.

## Engineering Follow-Up

- Add at least one second WebGoat XSS lesson action so reflected-XSS coverage is not represented by a single route.
- Track route-level coverage explicitly so header-only signal does not masquerade as broad scanner success.
- Keep WebGoat maturity claims conservative until more than one SQLi lesson route is benchmarked intentionally.
