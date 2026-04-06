"""CSRF vulnerability scanner plugin."""

import logging
from urllib.parse import urlparse

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target
from nightowl.utils.web_discovery import discover_web_attack_surface

logger = logging.getLogger("nightowl")

CSRF_TOKEN_NAMES = {"csrf_token", "_token", "authenticity_token", "csrfmiddlewaretoken", "__RequestVerificationToken", "_csrf", "csrf", "token", "nonce"}


class CSRFScannerPlugin(ScannerPlugin):
    name = "csrf-scanner"
    description = "Detect forms missing CSRF protection"
    version = "1.0.0"
    stage = "scan"
    config_schema = {
        "discovery_depth": (int, 1),
        "discovery_max_pages": (int, 6),
        "discovery_max_forms": (int, 12),
    }

    @staticmethod
    def _default_form_value(_param_name: str) -> str:
        return "test"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with self.create_http_client() as client:
                await self.bootstrap_auth(client)
                resp = await client.get(url, headers=self.get_request_headers())
                discovery = await discover_web_attack_surface(
                    client,
                    str(resp.url),
                    default_value_fn=self._default_form_value,
                    max_depth=self.config.get("discovery_depth", 1),
                    max_pages=self.config.get("discovery_max_pages", 6),
                    max_forms=self.config.get("discovery_max_forms", 12),
                    request_headers=self.get_request_headers(),
                    wait_hook=self.wait_request_delay,
                )

                page_samesite: dict[str, bool] = {}
                for page_url in discovery.visited_pages or [str(resp.url)]:
                    try:
                        page_resp = await client.get(page_url, headers=self.get_request_headers())
                    except Exception:
                        await self.wait_request_delay()
                        continue
                    cookies_header = page_resp.headers.get("set-cookie", "")
                    page_samesite[page_url] = "samesite" in cookies_header.lower()
                    await self.wait_request_delay()

                for form in discovery.forms:
                    method = form.method.upper()
                    if method == "GET":
                        continue

                    input_names = {name.lower() for name in form.params}
                    has_csrf_token = bool(input_names & CSRF_TOKEN_NAMES)
                    page_key = form.page_url
                    has_samesite = page_samesite.get(page_key, False)
                    action_path = urlparse(form.action_url).path or form.action_url

                    if not has_csrf_token and not has_samesite:
                        findings.append(Finding(
                            title=f"Form without CSRF protection: {action_path}",
                            severity=Severity.MEDIUM,
                            cvss_score=4.3,
                            description=f"POST form at {action_path} has no CSRF token and no SameSite cookie",
                            evidence=(
                                f"Page: {form.page_url}\n"
                                f"Form action: {form.action_url}\n"
                                f"Method: {method}\n"
                                f"Inputs: {', '.join(sorted(input_names))}\n"
                                "No CSRF token found\n"
                                "No SameSite cookie attribute"
                            ),
                            remediation="Add CSRF tokens to all state-changing forms. Set SameSite=Strict or Lax on session cookies.",
                            category="csrf",
                            references=["https://owasp.org/www-community/attacks/csrf"],
                        ))

        except Exception as e:
            logger.warning(f"CSRF scan failed for {url}: {e}")

        return findings
