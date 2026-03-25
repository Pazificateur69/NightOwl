"""CSRF vulnerability scanner plugin."""

import logging

import httpx
from bs4 import BeautifulSoup

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

CSRF_TOKEN_NAMES = {"csrf_token", "_token", "authenticity_token", "csrfmiddlewaretoken", "__RequestVerificationToken", "_csrf", "csrf", "token", "nonce"}


class CSRFScannerPlugin(ScannerPlugin):
    name = "csrf-scanner"
    description = "Detect forms missing CSRF protection"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                resp = await client.get(url)
                soup = BeautifulSoup(resp.text, "html.parser")

                # Check SameSite cookie
                cookies_header = resp.headers.get("set-cookie", "")
                has_samesite = "samesite" in cookies_header.lower()

                for form in soup.find_all("form"):
                    method = form.get("method", "GET").upper()
                    if method == "GET":
                        continue

                    action = form.get("action", url)
                    input_names = {inp.get("name", "").lower() for inp in form.find_all("input")}
                    has_csrf_token = bool(input_names & CSRF_TOKEN_NAMES)

                    if not has_csrf_token and not has_samesite:
                        findings.append(Finding(
                            title=f"Form without CSRF protection: {action}",
                            severity=Severity.MEDIUM,
                            cvss_score=4.3,
                            description=f"POST form at {action} has no CSRF token and no SameSite cookie",
                            evidence=f"Form action: {action}\nMethod: {method}\nInputs: {', '.join(input_names)}\nNo CSRF token found\nNo SameSite cookie attribute",
                            remediation="Add CSRF tokens to all state-changing forms. Set SameSite=Strict or Lax on session cookies.",
                            category="csrf",
                            references=["https://owasp.org/www-community/attacks/csrf"],
                        ))

        except Exception as e:
            logger.warning(f"CSRF scan failed for {url}: {e}")

        return findings
