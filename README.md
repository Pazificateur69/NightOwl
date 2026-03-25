<p align="center">
  <img src="https://em-content.zobj.net/source/apple/391/owl_1f989.png" width="120" alt="NightOwl"/>
</p>

<h1 align="center">NightOwl</h1>

<p align="center">
  <strong>The most complete open-source penetration testing framework.</strong><br/>
  57 automated scanner modules. Full pentest pipeline. Zero manual work.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Modules-57-cyan?style=for-the-badge" alt="57 Modules"/>
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT"/>
  <img src="https://img.shields.io/badge/OWASP-Top%2010-red?style=for-the-badge" alt="OWASP"/>
</p>

<p align="center">
  <a href="#installation">Install</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#all-57-modules">All Modules</a> &bull;
  <a href="#web-dashboard">Dashboard</a> &bull;
  <a href="#custom-plugins">Plugins</a> &bull;
  <a href="#docker">Docker</a>
</p>

---

## Why NightOwl?

| Feature | NightOwl | OWASP ZAP | Nikto | Nuclei |
|---------|----------|-----------|-------|--------|
| Modules | **57** | ~15 | ~7 | Templates |
| Full auto pipeline | **Yes** | Partial | No | No |
| Web + Network + AD | **All-in-one** | Web only | Web only | Templates |
| JWT attacks | **Yes** | No | No | Basic |
| GraphQL introspection | **Yes** | Plugin | No | Basic |
| WebSocket fuzzing | **Yes** | No | No | No |
| Prototype pollution | **Yes** | No | No | Basic |
| Cache poisoning | **Yes** | No | No | Basic |
| Race condition detection | **Yes** | No | No | No |
| HTTP smuggling | **Yes** | No | No | Basic |
| Subdomain takeover | **Yes** | No | No | Templates |
| Cloud enum (AWS/GCP/Azure) | **Yes** | No | No | No |
| JS secrets extraction | **Yes** | No | No | Basic |
| IDOR detection | **Yes** | No | No | No |
| Active Directory | **Yes** | No | No | No |
| Metasploit integration | **Yes** | No | No | No |
| Post-exploitation | **Yes** | No | No | No |
| Web dashboard | **Yes** | Yes | No | No |
| Plugin system | **Yes** | Yes | No | Yes |
| Report gen (HTML/PDF/MD) | **Yes** | Yes | Basic | Basic |
| 100% free & open-source | **Yes** | Yes | Yes | Yes |

---

## Installation

```bash
git clone https://github.com/Pazificateur69/NightOwl.git
cd NightOwl

# Basic install
pip install -e .

# Full install (all dependencies)
pip install -e ".[full]"

# Development
pip install -e ".[dev,full]"
```

**Requirements:** Python 3.11+ | nmap (optional, for port scanning)

---

## Quick Start

```bash
# Full automated pentest (recon -> scan -> exploit -> post -> report)
nightowl full https://target.com --mode auto

# Reconnaissance only
nightowl recon target.com --full

# Web vulnerability scan (all 27 web modules)
nightowl scan web https://target.com --all

# Network infrastructure scan
nightowl scan network 192.168.1.0/24 --vuln

# Active Directory pentest
nightowl scan ad 10.0.0.1 --domain CORP.LOCAL --user admin --password pass

# Generate HTML report
nightowl report <scan-id> --format html

# Launch web dashboard
nightowl dashboard --port 8080

# List all available modules
nightowl plugins --list
```

### One-liner: full pentest with report

```bash
nightowl full https://target.com --mode auto && nightowl report latest --format html
```

---

## All 57 Modules

### Reconnaissance (12 modules)

| Module | Description |
|--------|-------------|
| `dns-enum` | DNS records (A, MX, NS, TXT, SOA, zone transfer) |
| `subdomain-enum` | Subdomain bruteforce via DNS |
| `port-scanner` | TCP/UDP port scanning (nmap) |
| `service-fingerprint` | Banner grabbing, service identification |
| `whois-lookup` | WHOIS registration data |
| `tech-detect` | CMS, framework, library detection (WordPress, React, etc.) |
| `web-spider` | Crawl links, forms, parameters |
| `cloud-enum` | **AWS S3, Azure Blob, GCP Storage, Firebase enumeration** |
| `subdomain-takeover` | **Dangling DNS / subdomain takeover (25+ services)** |
| `email-harvester` | **Email, phone, social media harvesting** |
| `js-analyzer` | **JavaScript secrets extraction (API keys, tokens, endpoints)** |
| `secrets-scanner` | **Exposed .git, .env, backups, config files (40+ paths)** |

### Web Security (27 modules)

| Module | Description | Category |
|--------|-------------|----------|
| `header-analyzer` | Security headers audit | OWASP A05 |
| `sqli-scanner` | SQL injection (error, blind, time-based) | OWASP A03 |
| `xss-scanner` | Reflected XSS with multiple encodings | OWASP A03 |
| `csrf-scanner` | Missing CSRF tokens + SameSite | OWASP A08 |
| `ssrf-scanner` | Server-Side Request Forgery | OWASP A10 |
| `path-traversal` | LFI / directory traversal | OWASP A01 |
| `dir-bruteforce` | Hidden directory/file discovery | OWASP A05 |
| `ssl-analyzer` | TLS config, certs, weak ciphers | OWASP A02 |
| `cors-checker` | CORS misconfiguration | OWASP A05 |
| `auth-tester` | Default credential testing | OWASP A07 |
| `api-scanner` | REST/GraphQL/Swagger discovery | OWASP A01 |
| `waf-detect` | **WAF fingerprinting (Cloudflare, AWS, Akamai, etc.)** |  |
| `jwt-attack` | **JWT alg:none, weak secrets, expired tokens** |  |
| `graphql-introspect` | **GraphQL schema dump + sensitive type detection** |  |
| `websocket-fuzzer` | **WebSocket XSS/SQLi/auth bypass fuzzing** |  |
| `ssti-scanner` | **Server-Side Template Injection (Jinja2, Twig, etc.)** |  |
| `xxe-scanner` | **XML External Entity injection** |  |
| `deserialization-scanner` | **Java/PHP/Python/NET deserialization** |  |
| `crlf-injection` | **HTTP header injection via CRLF** |  |
| `open-redirect` | **Open redirect detection** |  |
| `http-smuggling` | **HTTP Request Smuggling (CL.TE, TE.CL)** |  |
| `param-miner` | **Hidden parameter discovery (like Burp Param Miner)** |  |
| `cache-poisoning` | **Web cache poisoning via unkeyed headers** |  |
| `race-condition` | **Race condition / TOCTOU detection** |  |
| `prototype-pollution` | **JS prototype pollution (client + server)** |  |
| `host-header-injection` | **Host header attacks + password reset poisoning** |  |
| `idor-scanner` | **Insecure Direct Object Reference detection** |  |

### Network (8 modules)

| Module | Description |
|--------|-------------|
| `deep-port-scan` | Deep scan with nmap NSE scripts |
| `vuln-matcher` | CVE matching by service/version |
| `smb-enum` | SMB shares + null session testing |
| `snmp-scanner` | SNMP community string bruteforce |
| `ssh-audit` | SSH cipher/algorithm audit |
| `ftp-scanner` | Anonymous FTP access testing |
| `network-map` | Host discovery / ping sweep |

### Active Directory (4 modules)

| Module | Description |
|--------|-------------|
| `ldap-enum` | LDAP user/group/OU enumeration |
| `kerberos-scanner` | AS-REP Roasting, Kerberoasting |
| `password-spray` | Rate-limited password spraying |
| `ad-recon` | Domain info, password policies, trusts |

### Exploitation (3 modules)

| Module | Description |
|--------|-------------|
| `msf-bridge` | Metasploit Framework RPC bridge |
| `exploit-db` | CVE-to-exploit matching (15+ CVEs) |
| `auto-exploit` | Automatic exploit selection by CVSS |

### Post-Exploitation (4 modules)

| Module | Description |
|--------|-------------|
| `privesc-check` | Privilege escalation vectors (Linux + Windows) |
| `file-enum` | Sensitive file discovery |
| `credential-dump` | Credential storage detection |
| `lateral-movement` | Lateral movement opportunities |

---

## Full Auto Pipeline

NightOwl runs a complete pentest automatically in 5 stages:

```
RECON ──> SCAN ──> EXPLOIT ──> POST-EXPLOIT ──> REPORT
  │         │         │            │               │
  │         │         │            │               └─ HTML/PDF/MD report
  │         │         │            └─ Privesc, creds, lateral movement
  │         │         └─ Auto-exploit based on CVSS score
  │         └─ 27 web + 8 network + 4 AD modules
  └─ 12 recon modules (DNS, ports, cloud, secrets, JS)
```

### 3 Modes

| Mode | Behavior |
|------|----------|
| `auto` | Runs everything without stopping. Full hands-off. |
| `semi` | Pauses before exploitation to ask confirmation. |
| `manual` | Asks before every stage. Full control. |

---

## Web Dashboard

```bash
nightowl dashboard
```

Open `http://127.0.0.1:8080`:

- **Dark theme** UI built with Tailwind CSS
- Real-time scan monitoring
- Findings browser with severity filters
- Severity distribution charts (Chart.js)
- Report generation and export
- REST API for integration

---

## Reports

```bash
# HTML report with charts
nightowl report <scan-id> --format html

# PDF report
nightowl report <scan-id> --format pdf

# Markdown for Git/wiki
nightowl report <scan-id> --format md
```

Reports include:
- Executive summary with severity counts
- Findings sorted by CVSS score
- Detailed evidence and remediation for each finding
- Interactive severity chart (HTML)

---

## Custom Plugins

Extend NightOwl with your own modules. Drop a `.py` file in `plugins/`:

```python
from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

class MyScanner(ScannerPlugin):
    name = "my-scanner"
    description = "My custom vulnerability scanner"
    stage = "scan"  # recon | scan | exploit | post

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        # Your scanning logic here
        return findings
```

That's it. NightOwl auto-discovers it on next run.

---

## Configuration

```yaml
# nightowl.yaml
mode: auto
threads: 10
timeout: 30

scope:
  allowed_hosts:
    - target.com
    - "*.target.com"
  allowed_networks:
    - 192.168.1.0/24
  excluded_hosts:
    - production.target.com

rate_limit:
  requests_per_second: 10
  burst: 20
```

---

## Docker

```bash
# NightOwl + dashboard
docker-compose -f docker/docker-compose.yml up

# With vulnerable practice targets (DVWA + Juice Shop)
docker-compose -f docker/docker-compose.yml --profile targets up
```

---

## Architecture

```
nightowl/
├── core/           # Async engine, plugin system, pipeline, events
├── models/         # Pydantic v2 models (Finding, Target, Scan, Config)
├── config/         # YAML loader, scope manager, defaults
├── db/             # SQLAlchemy + SQLite persistence
├── modules/        # 57 built-in scanner plugins
│   ├── recon/      # 12 reconnaissance modules
│   ├── web/        # 27 web security modules
│   ├── network/    # 8 network modules
│   ├── ad/         # 4 Active Directory modules
│   ├── exploit/    # 3 exploitation modules
│   └── postexploit/# 4 post-exploitation modules
├── cli/            # Click CLI + Rich terminal UI
├── web/            # FastAPI dashboard + REST API
├── reporting/      # HTML/PDF/Markdown report generation
└── utils/          # Logger, rate limiter, network helpers
```

---

## Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Write your module following the plugin pattern
4. Add tests in `tests/`
5. Submit a Pull Request

### Ideas for contributions
- New scanner modules (cloud-specific, IoT, mobile)
- Wordlists for different languages/frameworks
- Dashboard improvements
- Integration with other tools (Nessus, OpenVAS)
- Additional report templates

---

## Legal Disclaimer

NightOwl is designed for **authorized security testing only**. Always obtain explicit written permission before scanning any target. Unauthorized scanning is illegal. The authors are not responsible for any misuse of this tool.

**Use responsibly. Hack ethically.**

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with Python, async power, and late-night coffee.</sub>
</p>
