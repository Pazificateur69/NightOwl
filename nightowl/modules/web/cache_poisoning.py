"""Web cache poisoning detection plugin."""

import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Headers that might be reflected but unkeyed (cache poisoning vectors)
POISON_HEADERS = {
    "X-Forwarded-Host": "nightowl-poison-test.evil.com",
    "X-Forwarded-Scheme": "nothttps",
    "X-Original-URL": "/nightowl-cache-test",
    "X-Rewrite-URL": "/nightowl-cache-test",
    "X-Forwarded-For": "nightowl-poison-xff",
    "X-Host": "nightowl-poison-xhost.evil.com",
    "X-Forwarded-Server": "nightowl-poison-xfs.evil.com",
    "X-HTTP-Method-Override": "POST",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Original-Host": "nightowl-poison-original.evil.com",
    "Forwarded": "host=nightowl-poison-fwd.evil.com",
    "True-Client-IP": "127.0.0.1",
}


class CachePoisoningPlugin(ScannerPlugin):
    name = "cache-poisoning"
    description = "Detect web cache poisoning via unkeyed headers"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                # Baseline
                baseline = await client.get(url)
                baseline_body = baseline.text

                # Check if caching is present
                cache_headers = {k.lower(): v for k, v in baseline.headers.items()
                               if k.lower() in ("cache-control", "x-cache", "age", "cf-cache-status", "x-varnish", "via")}

                if cache_headers:
                    findings.append(Finding(
                        title="Caching detected",
                        severity=Severity.INFO,
                        evidence=f"Cache headers: {cache_headers}",
                        category="cache-poisoning",
                    ))

                # Test each header
                for header, value in POISON_HEADERS.items():
                    try:
                        resp = await client.get(url, headers={header: value})

                        # Check if our injected value is reflected in response
                        if value in resp.text and value not in baseline_body:
                            # Potential cache poisoning - the unkeyed header value is reflected
                            sev = Severity.HIGH
                            if "host" in header.lower() or "url" in header.lower():
                                sev = Severity.CRITICAL

                            findings.append(Finding(
                                title=f"Cache poisoning via {header}",
                                severity=sev,
                                cvss_score=9.0 if sev == Severity.CRITICAL else 7.5,
                                description=f"Unkeyed header {header} is reflected in response body, enabling cache poisoning",
                                evidence=f"Header: {header}: {value}\nValue reflected in response body\nCache headers: {cache_headers}",
                                remediation="Include all user-controlled headers in cache key. Use Vary header. Disable caching for dynamic content.",
                                category="cache-poisoning",
                                references=["https://portswigger.net/research/practical-web-cache-poisoning"],
                            ))

                        # Check if header changes redirect
                        if resp.status_code in (301, 302, 307, 308):
                            location = resp.headers.get("location", "")
                            if value in location:
                                findings.append(Finding(
                                    title=f"Cache poisoning redirect via {header}",
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.3,
                                    description=f"Header {header} controls redirect Location header",
                                    evidence=f"Header: {header}: {value}\nLocation: {location}",
                                    remediation="Do not use unvalidated headers for redirects. Fix web server/proxy configuration.",
                                    category="cache-poisoning",
                                ))

                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        continue

        except Exception as e:
            logger.warning(f"Cache poisoning scan failed: {e}")

        return findings
