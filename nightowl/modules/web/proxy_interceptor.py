"""HTTP traffic crawler and analyzer.

NOTE: This is NOT an intercepting proxy (like Burp or mitmproxy). It crawls
the target site, logs request/response pairs, and flags suspicious patterns
in the traffic (sensitive data leaks, error messages, exposed endpoints).

For actual traffic interception, use a dedicated tool like mitmproxy or Burp.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class RequestLog:
    """Stores crawled request/response pairs."""

    def __init__(self):
        self.entries: list[dict] = []

    def add(self, method: str, url: str, status: int, headers: dict,
            request_body: str = "", response_body: str = "", duration: float = 0):
        self.entries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "request_headers": dict(headers),
            "request_body": request_body[:2000],
            "response_body": response_body[:5000],
            "duration_ms": round(duration * 1000, 1),
        })

    def get_suspicious(self) -> list[dict]:
        """Find suspicious patterns in logged traffic."""
        suspicious = []
        for entry in self.entries:
            body = entry.get("response_body", "").lower()
            url = entry.get("url", "").lower()

            # Sensitive data in responses
            if any(kw in body for kw in ["password", "secret", "api_key", "apikey", "token", "private_key"]):
                suspicious.append({**entry, "reason": "Sensitive data in response body"})

            # Error messages leaking info
            if any(kw in body for kw in ["stack trace", "traceback", "exception", "sql syntax", "mysql", "postgresql"]):
                suspicious.append({**entry, "reason": "Verbose error message / stack trace"})

            # Mixed content
            if entry.get("status") == 200 and "http://" in url:
                suspicious.append({**entry, "reason": "Unencrypted HTTP traffic"})

            # Server errors
            if entry.get("status", 0) >= 500:
                suspicious.append({**entry, "reason": f"Server error: {entry['status']}"})

            # Sensitive endpoints without auth
            if any(p in url for p in ["/admin", "/debug", "/console", "/phpmyadmin", "/.env"]):
                if entry.get("status") in (200, 301, 302):
                    suspicious.append({**entry, "reason": "Sensitive endpoint accessible"})

        return suspicious


class TrafficAnalyzerPlugin(ScannerPlugin):
    name = "traffic-analyzer"
    description = "Crawl target site and analyze HTTP traffic for sensitive data leaks, errors, and exposed endpoints"
    version = "1.0.0"
    stage = "scan"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.request_log = RequestLog()
        self.active_form_submission = bool(self.config.get("active_form_submission", False))

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []

        try:
            import httpx

            base_url = target.url or f"https://{target.host}"
            logger.info(f"[{self.name}] Crawling and analyzing traffic to {base_url}")

            # Crawl and log requests
            pages_to_visit = [base_url]
            visited = set()
            max_pages = self.config.get("max_pages", 20)

            forms_detected = 0
            async with self.create_http_client() as client:
                while pages_to_visit and len(visited) < max_pages:
                    url = pages_to_visit.pop(0)
                    if url in visited:
                        continue
                    visited.add(url)

                    try:
                        start = time.time()
                        resp = await client.get(url)
                        duration = time.time() - start

                        self.request_log.add(
                            method="GET",
                            url=str(resp.url),
                            status=resp.status_code,
                            headers=dict(resp.headers),
                            response_body=resp.text[:5000],
                            duration=duration,
                        )

                        # Extract more links to visit
                        if "text/html" in resp.headers.get("content-type", ""):
                            from bs4 import BeautifulSoup
                            soup = BeautifulSoup(resp.text, "html.parser")
                            for a in soup.find_all("a", href=True):
                                href = a["href"]
                                if href.startswith("/"):
                                    parsed = urlparse(base_url)
                                    full = f"{parsed.scheme}://{parsed.netloc}{href}"
                                    if full not in visited:
                                        pages_to_visit.append(full)
                                elif href.startswith(base_url):
                                    if href not in visited:
                                        pages_to_visit.append(href)

                            # Passive-by-default: record forms but do not submit them unless
                            # the operator explicitly enables active form submission.
                            for form in soup.find_all("form"):
                                forms_detected += 1
                                action = form.get("action", "")
                                method = form.get("method", "get").upper()
                                if self.active_form_submission and method == "POST" and action:
                                    form_url = urljoin(str(resp.url), action)
                                    try:
                                        start = time.time()
                                        post_resp = await client.post(form_url, data={"test": "nightowl"})
                                        self.request_log.add(
                                            method="POST", url=form_url,
                                            status=post_resp.status_code,
                                            headers=dict(post_resp.headers),
                                            request_body="test=nightowl",
                                            response_body=post_resp.text[:5000],
                                            duration=time.time() - start,
                                        )
                                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                                        logger.debug(f"Suppressed error: {exc}")

                    except Exception as e:
                        logger.debug(f"[{self.name}] Error visiting {url}: {e}")

            # Analyze logged traffic
            suspicious = self.request_log.get_suspicious()
            for s in suspicious:
                sev = Severity.MEDIUM
                if "Sensitive data" in s["reason"] or "Server error" in s["reason"]:
                    sev = Severity.HIGH
                elif "Sensitive endpoint" in s["reason"]:
                    sev = Severity.HIGH

                findings.append(Finding(
                    title=f"Traffic: {s['reason']}",
                    description=f"Traffic analysis found: {s['reason']}",
                    severity=sev,
                    category="traffic-analysis",
                    evidence=f"URL: {s['url']}\nMethod: {s['method']}\nStatus: {s['status']}\nDuration: {s['duration_ms']}ms",
                    remediation="Review the endpoint and fix the identified issue",
                    metadata={"traffic_entry": s},
                ))

            # Summary finding
            findings.append(Finding(
                title=f"Traffic Analysis: {len(self.request_log.entries)} requests, {len(suspicious)} suspicious",
                description=f"Crawled {len(visited)} pages, logged {len(self.request_log.entries)} requests",
                severity=Severity.INFO,
                category="traffic-analysis",
                evidence=f"Pages visited: {len(visited)}\nTotal requests: {len(self.request_log.entries)}\nSuspicious: {len(suspicious)}",
                metadata={
                    "total_requests": len(self.request_log.entries),
                    "suspicious_count": len(suspicious),
                    "pages_visited": len(visited),
                    "forms_detected": forms_detected,
                    "active_form_submission": self.active_form_submission,
                },
            ))

        except Exception as e:
            logger.error(f"[{self.name}] Traffic analysis error: {e}")

        return findings
