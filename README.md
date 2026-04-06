<p align="center">
  <img src="assets/banner.svg" alt="NightOwl" width="100%"/>
</p>

<p align="center">
  <strong>An open-source penetration testing framework under active hardening.</strong><br/>
  <em>72 modules. Full pipeline. Core modules are being benchmarked and stabilized.</em>
</p>

<p align="center">
  <a href="#install"><img src="https://img.shields.io/badge/install-one_liner-00ffcc?style=for-the-badge&logo=gnubash&logoColor=white" alt="Install"/></a>
  <a href="https://github.com/Pazificateur69/NightOwl/stargazers"><img src="https://img.shields.io/github/stars/Pazificateur69/NightOwl?style=for-the-badge&color=ff0040&logo=github" alt="Stars"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"/></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/></a>
</p>

<br/>

<p align="center">
  <img src="assets/demo.svg" alt="NightOwl Demo" width="100%"/>
</p>

<br/>

---

## Why NightOwl?

Most pentest tools do **one thing**. You end up juggling nmap, Nikto, sqlmap, Burp, Metasploit, and 15 other tools for a single assessment.

NightOwl aims to **unify** these into a single framework. Depending on scope, enabled modules, and target type, one command can orchestrate recon, scanning, and reporting from the same workflow.

```bash
nightowl full https://target.com --mode auto
```

NightOwl ships 72 modules covering DNS enumeration, port scanning, WAF detection, OWASP Top 10 testing, JWT attacks, HTTP smuggling, CMS scanning, and more. It's an **early-stage framework** — many modules are basic implementations that still need real-world testing and refinement.

> **Warning:** NightOwl is under active development. Test coverage is still limited. Detection accuracy varies by module. **Always verify findings manually** before reporting them. Do not rely on NightOwl as your only testing tool for production assessments.

## Current Positioning

NightOwl should currently be treated as:

- a multi-module offensive security framework for labs, learning, and pre-audit automation
- a project with a small core of prioritized modules under active hardening
- a complement to mature tools such as ZAP, Burp, Nuclei, sqlmap, and Metasploit

NightOwl should not yet be presented as a replacement for established professional tooling.

---

## Benchmarks

The comparison table below is a feature inventory, not a validated performance benchmark.
Real benchmark work is being tracked in [benchmarks/README.md](benchmarks/README.md) and raw sessions should be recorded from the local DVWA, Juice Shop, and WebGoat lab before making quality claims.

| Feature | NightOwl | OWASP ZAP | Nikto | Nuclei | Burp Free |
|---|:---:|:---:|:---:|:---:|:---:|
| **Modules** | **72** | ~12 | ~7 | templates | ~15 |
| **Auto full pipeline** | yes | no | no | no | no |
| **Recon + Scan + Exploit** | yes | scan only | scan only | scan only | scan only |
| **OWASP Top 10 coverage attempted** | 10/10 | 8/10 | 4/10 | 7/10 | 8/10 |
| **SSTI detection** | yes | no | no | basic | no |
| **JWT attacks** | yes | no | no | no | paid |
| **GraphQL introspection** | yes | no | no | basic | paid |
| **HTTP smuggling** | yes | no | no | basic | paid |
| **WebSocket fuzzing** | yes | no | no | no | paid |
| **Deserialization** | yes | no | no | basic | paid |
| **Race condition** | yes | no | no | no | paid |
| **Prototype pollution** | yes | no | no | no | paid |
| **Cache poisoning** | yes | no | no | basic | paid |
| **Active Directory** | yes | no | no | no | no |
| **Metasploit bridge** | yes | no | no | no | no |
| **Post-exploitation** | yes | no | no | no | no |
| **WordPress/CMS scan** | yes | no | yes | basic | paid |
| **Container/K8s audit** | yes | no | no | no | no |
| **CI/CD audit** | yes | no | no | no | no |
| **Database audit** | yes | no | no | no | no |
| **Email security** | yes | no | no | basic | no |
| **Dependency confusion** | yes | no | no | no | no |
| **Cloud IAM audit** | yes | no | no | no | no |
| **Hash cracker** | yes | no | no | no | no |
| **Compliance mapping** | yes | no | no | no | paid |
| **Scan diffing** | yes | no | no | no | paid |
| **Traffic analyzer** | yes | no | no | no | yes |
| **Web dashboard** | yes | yes | no | no | yes |
| **PDF/HTML reports** | yes | yes | no | no | paid |
| **Plugin system** | yes | yes | no | yes | paid |
| **CLI + Web** | both | web only | CLI only | CLI only | web only |
| **Price** | **Free** | Free | Free | Free | $449/yr |

> **Note:** These comparisons are based on feature availability, **not detection accuracy or quality**. NightOwl is an early-stage project and detection quality still varies significantly. This table shows what NightOwl *attempts* to cover, not what it proves at the level of mature tools.

## Core Modules And Maturity

The current hardening effort is focused on these core modules:

- `header-analyzer`
- `xss-scanner`
- `sqli-scanner`
- `cors-checker`
- `ssl-analyzer`
- `port-scanner`
- `deep-port-scan`
- `dir-bruteforce`

Current maturity labels:

- `recommended`: prioritized core modules under active hardening and benchmark preparation
- `usable-with-caution`: useful modules with partial confidence, still needing more evidence
- `experimental`: feature-present modules that should not be trusted without close manual validation

---

## All 72 Modules

### Reconnaissance (14 modules)
| Module | What it does |
|---|---|
| `dns-enum` | A/AAAA/MX/NS/TXT/SOA records, zone transfer attempts |
| `subdomain-enum` | Brute-force subdomain discovery with async DNS |
| `port-scanner` | TCP/UDP port scanning via nmap |
| `service-fingerprint` | Banner grabbing, HTTP header detection |
| `whois-lookup` | Registrar, creation/expiry dates, nameservers |
| `tech-detect` | CMS, framework, server, language detection |
| `web-spider` | Recursive crawling, link/form/parameter extraction |
| `cloud-enum` | AWS S3, Azure Blob, GCP bucket enumeration |
| `subdomain-takeover` | Detects dangling DNS pointing to deprovisioned services |
| `email-harvester` | Email discovery from HTML, metadata, headers |
| `js-analyzer` | API keys, endpoints, secrets in JavaScript files |
| `secrets-scanner` | Regex-based secret detection (AWS keys, tokens, passwords) |
| `dependency-confusion` | Detect private packages vulnerable to public registry hijack |
| `cloud-iam-audit` | AWS/GCP/Azure metadata exposure, IAM credential leaks |

### Web Security (34 modules)
| Module | What it does |
|---|---|
| `header-analyzer` | Missing security headers (HSTS, CSP, X-Frame, etc.) |
| `sqli-scanner` | Error-based, blind, time-based SQL injection |
| `xss-scanner` | Reflected XSS with multiple encoding bypasses |
| `csrf-scanner` | Missing CSRF tokens, SameSite cookie checks |
| `ssrf-scanner` | Internal IP/cloud metadata SSRF detection |
| `path-traversal` | LFI/RFI with encoding bypass variants |
| `dir-bruteforce` | Directory/file discovery with status code analysis |
| `ssl-analyzer` | TLS version, cipher strength, cert validation |
| `cors-checker` | Wildcard CORS, credential-allowing misconfigs |
| `auth-tester` | Default credentials, HTTP auth bypass |
| `api-scanner` | REST/GraphQL endpoint discovery, method enum |
| `waf-detect` | 30+ WAF fingerprints (Cloudflare, AWS, Imperva...) |
| `jwt-attack` | alg:none, weak secret brute-force, expired token reuse |
| `graphql-introspect` | Schema dump, sensitive type detection, unauth mutations |
| `websocket-fuzzer` | Auth bypass, XSS/SQLi/command injection over WebSocket |
| `ssti-scanner` | Jinja2, Twig, Freemarker, Velocity, ERB, EJS detection |
| `deserialization-scanner` | Java/PHP/Python/dotNET deserialization detection |
| `xxe-scanner` | XML external entity with file disclosure + SSRF |
| `crlf-injection` | HTTP header injection, response splitting |
| `open-redirect` | 17 bypass payloads across 30 common parameters |
| `http-smuggling` | CL.TE, TE.CL, TE.TE obfuscation detection |
| `param-miner` | Hidden parameter discovery via brute-force |
| `cache-poisoning` | Web cache poisoning via unkeyed headers |
| `race-condition` | TOCTOU race condition detection |
| `prototype-pollution` | JavaScript prototype pollution via URL params |
| `host-header-injection` | Host header attacks, password reset poisoning |
| `idor-scanner` | Insecure Direct Object Reference detection |
| `wordpress-scanner` | WP version, users, plugins, xmlrpc, debug.log exposure |
| `cms-scanner` | Drupal, Joomla, Magento, Shopify, Ghost, Laravel detection |
| `email-security` | SPF/DKIM/DMARC validation, email spoofing assessment |
| `dns-rebinding` | Host header validation, DNS rebinding attack detection |
| `protocol-fuzzer` | Mutation-based HTTP fuzzing (overflow, format strings, null) |
| `compliance-mapper` | Map findings to PCI-DSS, OWASP, NIST, ISO 27001 |
| `traffic-analyzer` | Crawl & analyze HTTP traffic for leaks, errors, and exposed endpoints |

### Network (10 modules)
| Module | What it does |
|---|---|
| `deep-port-scan` | nmap NSE scripts, version detection |
| `vuln-matcher` | Service/version to CVE matching |
| `smb-enum` | SMB share enumeration, anonymous/null session |
| `snmp-scanner` | Default community string detection |
| `ssh-audit` | Weak algorithms, key types, protocol audit |
| `ftp-scanner` | Anonymous FTP access, writable directory check |
| `network-map` | Ping sweep, live host discovery |
| `container-audit` | Docker socket, K8s API, etcd, kubelet exposure |
| `cicd-audit` | Jenkins, GitLab, GitHub Actions, Drone, ArgoCD, SonarQube |
| `database-audit` | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch unauth check |

### Active Directory (4 modules)
| Module | What it does |
|---|---|
| `ldap-enum` | Users, groups, OUs, domain info via LDAP |
| `kerberos-scanner` | AS-REP Roasting, Kerberoasting |
| `password-spray` | Rate-limited password spraying |
| `ad-recon` | Domain controllers, trusts, password policies |

### Exploitation (5 modules)
| Module | What it does |
|---|---|
| `msf-bridge` | Metasploit RPC integration |
| `exploit-db` | CVE to exploit mapping (30+ known exploits) |
| `auto-exploit` | Automatic exploit selection by CVSS score |
| `hash-cracker` | Dictionary attack on MD5/SHA/bcrypt/NTLM hashes |
| `reverse-shell-gen` | Generate reverse shells (bash, python, php, powershell, nc...) |

### Post-Exploitation (5 modules)
| Module | What it does |
|---|---|
| `privesc-check` | SUID, sudo, kernel, unquoted service paths |
| `file-enum` | Sensitive files (.env, SSH keys, configs) |
| `credential-dump` | Credential storage location identification |
| `lateral-movement` | Network pivot opportunity detection |
| `diff-scanner` | Compare scans to detect new, fixed, and changed findings |

---

## Install

### Quick install

> **Security note:** Review [install.sh](install.sh) before running. Piping to bash is convenient but skips inspection.

```bash
curl -sSL https://raw.githubusercontent.com/Pazificateur69/NightOwl/main/install.sh | bash
```

### Manual (recommended)

```bash
git clone https://github.com/Pazificateur69/NightOwl.git
cd NightOwl
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
nightowl --help
```

### Docker

```bash
docker build -t nightowl -f docker/Dockerfile .
docker run -it nightowl nightowl --help
```

**Requirements:** Python 3.11+ | Optional: nmap, Metasploit

---

## Usage

### Full auto pentest (one command)
```bash
nightowl full https://target.com --mode auto
```

### Reconnaissance only
```bash
nightowl recon target.com --full
nightowl recon target.com --dns --ports --subdomains
```

### Web vulnerability scan
```bash
nightowl scan web https://target.com --all
nightowl scan web https://target.com --core
nightowl scan web https://target.com --sqli --xss
```

### Network scan
```bash
nightowl scan network 192.168.1.0/24 --ports 1-65535 --vuln
```

### Active Directory
```bash
nightowl scan ad 10.0.0.1 --domain corp.local --user admin
```

### Generate report
```bash
nightowl report <scan-id> --format html --output ./reports
nightowl report <scan-id> --format pdf
```

### Web dashboard
```bash
nightowl dashboard --port 8080
```

### Run a local benchmark session
```bash
make bench-up
make bench-run-dvwa
```

### List all plugins
```bash
nightowl plugins --list
nightowl plugins --list --core-only
nightowl plugins --list --maturity recommended
```

---

## Scan Modes

| Mode | Behavior |
|---|---|
| `auto` | Runs everything automatically, no human intervention |
| `semi` | Pauses before exploitation stages for user confirmation |
| `manual` | Confirms every stage before proceeding |

```bash
nightowl full target.com --mode auto    # Full autopilot
nightowl full target.com --mode semi    # Confirm before exploit
nightowl full target.com --mode manual  # Confirm every stage
```

---

## Custom Plugins

Create your own scanner modules:

```python
# plugins/my_scanner.py
from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

class MyScanner(ScannerPlugin):
    name = "my-scanner"
    description = "Custom vulnerability scanner"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        # Your scanning logic here
        return [
            Finding(
                title="Custom vulnerability found",
                severity=Severity.HIGH,
                description="Details about the vulnerability",
                evidence="HTTP response showing the issue",
                remediation="How to fix it",
            )
        ]
```

Drop it in `plugins/` and NightOwl auto-discovers it.

---

## Architecture

```
nightowl/
├── core/           Engine, pipeline, plugin system, async events
├── models/         Pydantic models (Finding, Target, Scan, Config)
├── config/         YAML config, scope management, defaults
├── db/             SQLAlchemy + SQLite persistence
├── modules/        72 scanner plugins across 6 stages
│   ├── recon/      DNS, ports, subdomains, cloud, JS analysis
│   ├── web/        OWASP Top 10 + advanced web attacks
│   ├── network/    SMB, SNMP, SSH, FTP, CVE matching
│   ├── ad/         LDAP, Kerberos, password spray
│   ├── exploit/    Metasploit bridge, auto-exploit
│   └── postexploit/ Privesc, credentials, lateral movement
├── cli/            Click CLI + Rich terminal UI
├── web/            FastAPI dashboard + real-time WebSocket
├── reporting/      HTML, PDF, Markdown report generation
└── utils/          Logging, rate limiting, network helpers
```

**Pipeline:** `RECON` > `SCAN` > `EXPLOIT` > `POST-EXPLOIT` > `REPORT`

---

## Configuration

```yaml
# configs/default.yaml
scope:
  allowed_hosts:
    - "*.target.com"
  allowed_networks:
    - "192.168.1.0/24"

rate_limit:
  requests_per_second: 10
  burst: 20

mode: semi
threads: 10
timeout: 30
output_dir: ./reports
```

---

## Roadmap

- [ ] Nuclei template compatibility
- [ ] Burp Suite extension bridge
- [ ] Collaborative multi-user scans
- [ ] Scheduled recurring scans
- [ ] Slack/Discord notifications
- [ ] Custom wordlist management
- [ ] Scan diffing (compare two scans)
- [ ] CVSS v4.0 scoring

---

## Contributing

Pull requests welcome. For major changes, open an issue first.

```bash
git clone https://github.com/Pazificateur69/NightOwl.git
cd NightOwl
make dev      # Install with dev dependencies
make test     # Run tests
make lint     # Lint code
```

---

## Disclaimer

NightOwl is designed for **authorized security testing only**. Always obtain written permission before scanning any target. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse.

---

## License

[MIT](LICENSE) - Use it, fork it, build on it.

<p align="center">
  <img src="assets/logo.svg" width="80"/>
  <br/>
  <strong>NightOwl</strong> - See everything. Miss nothing.
</p>
