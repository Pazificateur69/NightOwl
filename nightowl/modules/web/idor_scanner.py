"""Insecure Direct Object Reference (IDOR) scanner."""

import logging
import re

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

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

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                # Get initial response
                resp = await client.get(url)

                # Check URL for numeric IDs
                for pattern, id_type in IDOR_PATTERNS:
                    match = re.search(pattern, url)
                    if match:
                        original_id = match.group(1)
                        await self._test_idor(client, url, original_id, pattern, id_type, findings)

                # Also scan links in the page for IDOR-susceptible URLs
                for pattern, id_type in IDOR_PATTERNS:
                    matches = re.findall(pattern, resp.text)
                    for original_id in set(matches[:5]):
                        # Construct test URLs from page links
                        link_pattern = re.search(r'href=["\']([^"\']*' + re.escape(original_id) + r'[^"\']*)["\']', resp.text)
                        if link_pattern:
                            test_url = link_pattern.group(1)
                            if not test_url.startswith("http"):
                                test_url = url.rstrip("/") + "/" + test_url.lstrip("/")
                            await self._test_idor(client, test_url, original_id, pattern, id_type, findings)

        except Exception as e:
            logger.warning(f"IDOR scan failed: {e}")

        return findings

    async def _test_idor(self, client, url, original_id, pattern, id_type, findings):
        try:
            original_resp = await client.get(url)
            if original_resp.status_code != 200:
                return

            # Test with adjacent IDs
            test_ids = [str(int(original_id) + i) for i in [1, -1, 2, 100]]

            for test_id in test_ids:
                modified_url = re.sub(re.escape(original_id), test_id, url, count=1)
                if modified_url == url:
                    continue

                try:
                    test_resp = await client.get(modified_url)

                    # If we get 200 with different content, potential IDOR
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
                        return  # One finding per URL pattern
                except Exception:
                    continue
        except Exception:
            pass
