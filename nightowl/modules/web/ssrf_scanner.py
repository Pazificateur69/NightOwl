"""Server-Side Request Forgery scanner plugin."""

import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0.0.0.0",
    "http://2130706433",  # 127.0.0.1 as decimal
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "local-hostname",  # AWS metadata
    "root:x:0:0", "localhost", "127.0.0.1",
    "computeMetadata",  # GCP
]

URL_PARAM_NAMES = {"url", "uri", "path", "redirect", "next", "target", "dest", "destination", "rurl", "return_url", "go", "link", "fetch", "proxy", "callback", "page"}


class SSRFScannerPlugin(ScannerPlugin):
    name = "ssrf-scanner"
    description = "Test for Server-Side Request Forgery vulnerabilities"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        test_params = {k: v for k, v in params.items() if k.lower() in URL_PARAM_NAMES}
        if not test_params:
            test_params = {k: v for k, v in params.items()}

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                for param_name in test_params:
                    for payload in SSRF_PAYLOADS:
                        qp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                        qp[param_name] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(qp)))

                        try:
                            resp = await client.get(test_url)
                            body = resp.text.lower()
                            for indicator in SSRF_INDICATORS:
                                if indicator.lower() in body:
                                    findings.append(Finding(
                                        title=f"Potential SSRF in parameter '{param_name}'",
                                        severity=Severity.HIGH,
                                        cvss_score=7.5,
                                        description=f"SSRF indicator found when injecting internal URL in {param_name}",
                                        evidence=f"URL: {test_url}\nPayload: {payload}\nIndicator: {indicator}",
                                        remediation="Validate and whitelist allowed URLs. Block internal IP ranges. Use allowlists for external requests.",
                                        category="ssrf",
                                        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                                    ))
                                    break
                        except Exception:
                            continue

        except Exception as e:
            logger.warning(f"SSRF scan failed: {e}")

        return findings
