"""JavaScript file analysis - extract secrets, endpoints, and sensitive data."""

import logging
import re

import httpx
from bs4 import BeautifulSoup

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"['\"][0-9a-zA-Z/+=]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "GitHub Token": r"gh[ps]_[0-9a-zA-Z]{36}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable": r"pk_live_[0-9a-zA-Z]{24,}",
    "Twilio SID": r"AC[0-9a-f]{32}",
    "Firebase": r"['\"]AIza[0-9A-Za-z_-]{35}['\"]",
    "Private Key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Bearer Token": r"[Bb]earer\s+[A-Za-z0-9_-]{20,}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "SendGrid Key": r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}",
    "Heroku API Key": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Generic Secret": r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]",
    "Password in Code": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
}

API_ENDPOINT_PATTERNS = [
    r"['\"`](\/api\/[a-zA-Z0-9/_-]+)['\"`]",
    r"['\"`](https?:\/\/[a-zA-Z0-9.-]+\/api\/[a-zA-Z0-9/_-]*)['\"`]",
    r"['\"`](\/v[0-9]+\/[a-zA-Z0-9/_-]+)['\"`]",
    r"fetch\(['\"`]([^'\"]+)['\"`]",
    r"axios\.\w+\(['\"`]([^'\"]+)['\"`]",
    r"\.get\(['\"`]([^'\"]+)['\"`]",
    r"\.post\(['\"`]([^'\"]+)['\"`]",
    r"XMLHttpRequest.*open\(['\"](\w+)['\"],\s*['\"]([^'\"]+)['\"]",
]


class JSAnalyzerPlugin(ScannerPlugin):
    name = "js-analyzer"
    description = "Analyze JavaScript files for secrets, API keys, endpoints, and sensitive data"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
                # Get main page and find all JS files
                resp = await client.get(base_url)
                soup = BeautifulSoup(resp.text, "html.parser")

                js_urls = set()
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if src.startswith("//"):
                        src = "https:" + src
                    elif src.startswith("/"):
                        src = base_url.rstrip("/") + src
                    elif not src.startswith("http"):
                        src = base_url.rstrip("/") + "/" + src
                    js_urls.add(src)

                # Also check inline scripts
                for script in soup.find_all("script"):
                    if script.string:
                        self._analyze_js(script.string, f"{base_url} (inline)", findings)

                # Analyze each JS file
                for js_url in list(js_urls)[:30]:
                    try:
                        js_resp = await client.get(js_url)
                        if js_resp.status_code == 200 and len(js_resp.text) < 5_000_000:
                            self._analyze_js(js_resp.text, js_url, findings)
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        continue

        except Exception as e:
            logger.warning(f"JS analysis failed: {e}")

        return findings

    def _analyze_js(self, code: str, source: str, findings: list[Finding]):
        # Search for secrets
        for secret_name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, code)
            if matches:
                for match in matches[:3]:
                    val = match if isinstance(match, str) else match[0]
                    # Mask the value
                    masked = val[:8] + "..." + val[-4:] if len(val) > 15 else val[:5] + "..."
                    findings.append(Finding(
                        title=f"Secret found: {secret_name}",
                        severity=Severity.CRITICAL if "key" in secret_name.lower() or "private" in secret_name.lower() else Severity.HIGH,
                        cvss_score=8.5,
                        description=f"{secret_name} found in JavaScript source",
                        evidence=f"Source: {source}\nType: {secret_name}\nValue: {masked}",
                        remediation="Remove secrets from client-side code. Use environment variables and server-side proxies.",
                        category="secrets",
                        metadata={"secret_type": secret_name, "source": source},
                    ))

        # Extract API endpoints
        endpoints = set()
        for pattern in API_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, code)
            for m in matches:
                ep = m if isinstance(m, str) else m[-1]
                if len(ep) > 3 and not ep.endswith((".js", ".css", ".png", ".jpg", ".svg")):
                    endpoints.add(ep)

        if endpoints:
            findings.append(Finding(
                title=f"API endpoints in JS ({len(endpoints)} found)",
                severity=Severity.INFO,
                description="API endpoints discovered in JavaScript source code",
                evidence=f"Source: {source}\nEndpoints:\n" + "\n".join(sorted(endpoints)[:30]),
                category="js-analysis",
                metadata={"endpoints": list(endpoints), "source": source},
            ))
