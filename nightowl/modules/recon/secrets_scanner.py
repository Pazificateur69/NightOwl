"""Secrets and sensitive data scanner - checks exposed files and common leaks."""

import asyncio
import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Files that should NEVER be publicly accessible
SENSITIVE_PATHS = {
    # Source control
    "/.git/HEAD": {"name": "Git repository exposed", "severity": Severity.CRITICAL, "indicator": "ref:"},
    "/.git/config": {"name": "Git config exposed", "severity": Severity.CRITICAL, "indicator": "[core]"},
    "/.svn/entries": {"name": "SVN repository exposed", "severity": Severity.HIGH, "indicator": "dir"},
    "/.hg/requires": {"name": "Mercurial repo exposed", "severity": Severity.HIGH, "indicator": ""},
    # Environment / Config
    "/.env": {"name": "Environment file exposed", "severity": Severity.CRITICAL, "indicator": "="},
    "/.env.local": {"name": ".env.local exposed", "severity": Severity.CRITICAL, "indicator": "="},
    "/.env.production": {"name": ".env.production exposed", "severity": Severity.CRITICAL, "indicator": "="},
    "/.env.backup": {"name": ".env backup exposed", "severity": Severity.CRITICAL, "indicator": "="},
    "/config.yml": {"name": "YAML config exposed", "severity": Severity.HIGH, "indicator": ""},
    "/config.json": {"name": "JSON config exposed", "severity": Severity.HIGH, "indicator": ""},
    "/wp-config.php.bak": {"name": "WordPress config backup", "severity": Severity.CRITICAL, "indicator": "DB_"},
    "/web.config": {"name": "ASP.NET config exposed", "severity": Severity.HIGH, "indicator": "configuration"},
    "/application.yml": {"name": "Spring config exposed", "severity": Severity.HIGH, "indicator": ""},
    "/appsettings.json": {"name": "ASP.NET settings exposed", "severity": Severity.HIGH, "indicator": "ConnectionStrings"},
    # Backups
    "/backup.sql": {"name": "SQL backup exposed", "severity": Severity.CRITICAL, "indicator": "INSERT"},
    "/database.sql": {"name": "Database dump exposed", "severity": Severity.CRITICAL, "indicator": "CREATE TABLE"},
    "/dump.sql": {"name": "SQL dump exposed", "severity": Severity.CRITICAL, "indicator": ""},
    "/backup.tar.gz": {"name": "Backup archive exposed", "severity": Severity.CRITICAL, "indicator": ""},
    "/backup.zip": {"name": "Backup ZIP exposed", "severity": Severity.CRITICAL, "indicator": ""},
    # Debug / Monitoring
    "/debug": {"name": "Debug page exposed", "severity": Severity.HIGH, "indicator": ""},
    "/phpinfo.php": {"name": "PHP info page", "severity": Severity.MEDIUM, "indicator": "phpinfo"},
    "/server-status": {"name": "Apache server-status", "severity": Severity.MEDIUM, "indicator": "Apache"},
    "/server-info": {"name": "Apache server-info", "severity": Severity.MEDIUM, "indicator": "Apache"},
    "/elmah.axd": {"name": "ELMAH error log", "severity": Severity.HIGH, "indicator": "Error"},
    "/trace.axd": {"name": "ASP.NET trace", "severity": Severity.HIGH, "indicator": "Trace"},
    "/_profiler": {"name": "Symfony profiler", "severity": Severity.MEDIUM, "indicator": "profiler"},
    # Credentials / Keys
    "/id_rsa": {"name": "SSH private key exposed", "severity": Severity.CRITICAL, "indicator": "PRIVATE KEY"},
    "/id_rsa.pub": {"name": "SSH public key exposed", "severity": Severity.LOW, "indicator": "ssh-rsa"},
    "/.ssh/authorized_keys": {"name": "SSH authorized_keys", "severity": Severity.HIGH, "indicator": "ssh-"},
    "/.htpasswd": {"name": "htpasswd file exposed", "severity": Severity.CRITICAL, "indicator": ":"},
    "/credentials.json": {"name": "Credentials file exposed", "severity": Severity.CRITICAL, "indicator": ""},
    # Docker / CI
    "/Dockerfile": {"name": "Dockerfile exposed", "severity": Severity.MEDIUM, "indicator": "FROM"},
    "/docker-compose.yml": {"name": "Docker Compose exposed", "severity": Severity.HIGH, "indicator": "services"},
    "/.docker/config.json": {"name": "Docker config exposed", "severity": Severity.CRITICAL, "indicator": "auths"},
    "/.github/workflows/": {"name": "GitHub Actions exposed", "severity": Severity.LOW, "indicator": ""},
    "/.gitlab-ci.yml": {"name": "GitLab CI config", "severity": Severity.MEDIUM, "indicator": "stages"},
    "/Jenkinsfile": {"name": "Jenkinsfile exposed", "severity": Severity.MEDIUM, "indicator": "pipeline"},
    # Package managers
    "/package.json": {"name": "NPM package.json", "severity": Severity.INFO, "indicator": "dependencies"},
    "/composer.json": {"name": "PHP Composer config", "severity": Severity.INFO, "indicator": "require"},
    "/Gemfile": {"name": "Ruby Gemfile", "severity": Severity.INFO, "indicator": "gem"},
    "/requirements.txt": {"name": "Python requirements", "severity": Severity.INFO, "indicator": "=="},
}


class SecretsScannerPlugin(ScannerPlugin):
    name = "secrets-scanner"
    description = "Scan for exposed secrets, config files, backups, and sensitive data"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = (target.url or f"https://{target.host}").rstrip("/")

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as client:
            for path, info in SENSITIVE_PATHS.items():
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200 and len(resp.content) > 0:
                        # Verify with indicator if provided
                        if info["indicator"] and info["indicator"] not in resp.text[:5000]:
                            continue
                        # Skip generic 200 pages (soft 404s)
                        if len(resp.content) < 10:
                            continue

                        findings.append(Finding(
                            title=info["name"],
                            severity=info["severity"],
                            cvss_score={"critical": 9.0, "high": 7.5, "medium": 5.3, "low": 3.7, "info": 0}.get(info["severity"].value, 0),
                            description=f"Sensitive file accessible at {path}",
                            evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}\nSize: {len(resp.content)} bytes\nPreview: {resp.text[:200]}",
                            remediation="Block access to sensitive files via web server config. Add to .htaccess or nginx deny rules.",
                            category="secrets",
                        ))
                except Exception:
                    continue
                await asyncio.sleep(0.05)

        return findings
