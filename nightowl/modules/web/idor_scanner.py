"""Insecure Direct Object Reference (IDOR) scanner."""

import logging
import re
from urllib.parse import urljoin

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target
from nightowl.utils.web_discovery import discover_web_attack_surface

logger = logging.getLogger("nightowl")

# Common IDOR patterns in URLs
IDOR_PATTERNS = [
    (r"/users?/(\d+)", "user ID"),
    (r"/accounts?/(\d+)", "account ID"),
    (r"/orders?/(\d+)", "order ID"),
    (r"/invoices?/(\d+)", "invoice ID"),
    (r"/documents?/(\d+)", "document ID"),
    (r"/files?/(\d+)", "file ID"),
    (r"/profiles?/(\d+)", "profile ID"),
    (r"/messages?/(\d+)", "message ID"),
    (r"/api/v\d+/\w+/(\d+)", "resource ID"),
    (r"[?&]id=(\d+)", "ID parameter"),
    (r"[?&]user_id=(\d+)", "user_id parameter"),
    (r"[?&]account_id=(\d+)", "account_id parameter"),
    (r"[?&]doc_id=(\d+)", "doc_id parameter"),
]


class IDORScannerPlugin(ScannerPlugin):
    name = "idor-scanner"
    description = "Detect Insecure Direct Object Reference by testing ID manipulation"
    version = "1.0.0"
    stage = "scan"
    config_schema = {
        "discovery_depth": (int, 1),
        "discovery_max_pages": (int, 6),
        "discovery_max_urls": (int, 10),
    }

    @staticmethod
    def _default_form_value(_param_name: str) -> str:
        return "1"

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
                    max_urls_with_params=self.config.get("discovery_max_urls", 10),
                    request_headers=self.get_request_headers(),
                    wait_hook=self.wait_request_delay,
                )

                candidate_urls = [str(resp.url)]
                for discovered_url in discovery.visited_pages + discovery.urls_with_params:
                    if discovered_url not in candidate_urls:
                        candidate_urls.append(discovered_url)

                tested_urls: set[str] = set()
                for candidate_url in candidate_urls:
                    for pattern, id_type in IDOR_PATTERNS:
                        match = re.search(pattern, candidate_url)
                        if not match:
                            continue
                        if candidate_url in tested_urls:
                            break
                        original_id = match.group(1)
                        await self._test_idor(client, candidate_url, original_id, id_type, findings)
                        tested_urls.add(candidate_url)
                        break

                for href_match in re.finditer(r'href=["\']([^"\']+)["\']', resp.text):
                    absolute_url = urljoin(str(resp.url), href_match.group(1))
                    if absolute_url in tested_urls:
                        continue
                    for pattern, id_type in IDOR_PATTERNS:
                        match = re.search(pattern, absolute_url)
                        if not match:
                            continue
                        original_id = match.group(1)
                        await self._test_idor(client, absolute_url, original_id, id_type, findings)
                        tested_urls.add(absolute_url)
                        break

        except Exception as e:
            logger.warning(f"IDOR scan failed: {e}")

        return findings

    async def _test_idor(self, client, url, original_id, id_type, findings):
        try:
            original_resp = await client.get(url, headers=self.get_request_headers())
            if original_resp.status_code != 200:
                return

            test_ids = [str(int(original_id) + i) for i in [1, -1, 2, 100]]

            for test_id in test_ids:
                modified_url = re.sub(re.escape(original_id), test_id, url, count=1)
                if modified_url == url:
                    continue

                try:
                    test_resp = await client.get(modified_url, headers=self.get_request_headers())
                    if (
                        test_resp.status_code == 200
                        and len(test_resp.content) > 100
                        and test_resp.text != original_resp.text
                    ):
                        findings.append(Finding(
                            title=f"Potential IDOR via {id_type}",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=f"Changing {id_type} from {original_id} to {test_id} returns different valid data",
                            evidence=f"Original: {url} ({len(original_resp.content)} bytes)\nModified: {modified_url} ({len(test_resp.content)} bytes)\nBoth return 200 with different content",
                            remediation="Implement proper authorization checks. Verify the requesting user owns the resource. Use UUIDs instead of sequential IDs.",
                            category="idor",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
                        ))
                        return
                except Exception as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue
                finally:
                    await self.wait_request_delay()
        except Exception as exc:
            logger.debug(f"Suppressed error: {exc}")
