"""Web Application Firewall detection plugin.

Detects and fingerprints WAF/CDN solutions by analyzing response headers,
sending known-blocked payloads, and checking for vendor-specific signatures.
"""

import logging
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Header-based WAF fingerprints: header_name -> (value_substring, waf_name)
WAF_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("cf-ray", "", "Cloudflare"),
    ("cf-cache-status", "", "Cloudflare"),
    ("server", "cloudflare", "Cloudflare"),
    ("server", "AkamaiGHost", "Akamai"),
    ("x-akamai-transformed", "", "Akamai"),
    ("x-cdn", "akamai", "Akamai"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-amz-cf-pop", "", "AWS CloudFront"),
    ("x-amzn-waf", "", "AWS WAF"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("server", "Sucuri", "Sucuri"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("x-cdn", "Incapsula", "Imperva Incapsula"),
    ("server", "BigIP", "F5 BIG-IP"),
    ("x-cnection", "", "F5 BIG-IP"),
    ("server", "Barracuda", "Barracuda WAF"),
    ("barra_counter_session", "", "Barracuda WAF"),
    ("server", "ModSecurity", "ModSecurity"),
    ("x-modsecurity-id", "", "ModSecurity"),
    ("server", "Varnish", "Varnish"),
    ("x-varnish", "", "Varnish"),
    ("server", "nginx", "Nginx (possible WAF)"),
    ("x-powered-by-plesk", "", "Plesk WAF"),
    ("x-denied-reason", "", "WatchGuard"),
    ("server", "FortiWeb", "Fortinet FortiWeb"),
    ("via", "nsfocus", "NSFOCUS WAF"),
    ("x-webcoment", "", "Webcoment Firewall"),
    ("x-qs-info", "", "QuantCast"),
    ("server", "DenyAll", "DenyAll WAF"),
    ("server", "DOSarrest", "DOSarrest"),
    ("x-dotdefender-denied", "", "dotDefender"),
]

# Response body patterns that indicate WAF blocking
WAF_BODY_SIGNATURES: list[tuple[str, str]] = [
    ("attention required! | cloudflare", "Cloudflare"),
    ("cf-error-details", "Cloudflare"),
    ("access denied | sucuri", "Sucuri"),
    ("sucuri website firewall", "Sucuri"),
    ("incapsula incident id", "Imperva Incapsula"),
    ("request unsuccessful. incapsula", "Imperva Incapsula"),
    ("powered by citrix netscaler", "Citrix NetScaler"),
    ("this request was blocked by the security rules", "ModSecurity"),
    ("not acceptable!", "ModSecurity"),
    ("web application firewall", "Generic WAF"),
    ("the requested url was rejected", "F5 BIG-IP ASM"),
    ("your request has been blocked", "Generic WAF"),
    ("request blocked", "Generic WAF"),
    ("akamai ghost", "Akamai"),
    ("access denied. your ip", "AWS WAF"),
    ("fortigate", "Fortinet FortiGate"),
    ("fortiweb", "Fortinet FortiWeb"),
    ("barracuda", "Barracuda WAF"),
    ("block_ref", "Sophos UTM WAF"),
]

# Payloads designed to trigger WAF rules
TRIGGER_PAYLOADS = [
    '<script>alert("NightOwl-WAF-Test")</script>',
    "' OR 1=1 --",
    "../../etc/passwd",
    "{{7*7}}",
    "; ls -la",
    'UNION SELECT ALL FROM information_schema AND " OR ""="',
]


class WAFDetectPlugin(ScannerPlugin):
    name = "waf-detect"
    description = "Detect and fingerprint Web Application Firewalls"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"
        detected_wafs: dict[str, list[str]] = {}  # waf_name -> list of evidence strings

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=10
            ) as client:
                # ── Phase 1: Passive header analysis on clean request ──
                try:
                    resp = await client.get(url)
                    self._check_headers(resp, detected_wafs)
                    self._check_body(resp.text, detected_wafs, "clean request")
                except Exception as e:
                    logger.debug(f"WAF detect clean request failed: {e}")

                # ── Phase 2: Active detection with trigger payloads ──
                parsed = urlparse(url)
                for payload in TRIGGER_PAYLOADS:
                    test_url = urlunparse(
                        parsed._replace(query=urlencode({"nightowl_test": payload}))
                    )
                    try:
                        resp = await client.get(test_url)

                        # WAFs typically return 403, 406, 429, or custom block pages
                        if resp.status_code in (403, 406, 429, 501, 503):
                            evidence = (
                                f"Payload: {payload[:60]}\n"
                                f"Status: {resp.status_code}\n"
                                f"URL: {test_url}"
                            )
                            self._check_headers(resp, detected_wafs)
                            self._check_body(resp.text, detected_wafs, payload[:40])

                            # If no specific WAF identified but request blocked
                            if not detected_wafs:
                                detected_wafs.setdefault("Unknown WAF", []).append(
                                    evidence
                                )

                        # Also re-check headers on non-blocked responses
                        self._check_headers(resp, detected_wafs)

                    except httpx.HTTPStatusError:
                        continue
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        continue

                # ── Phase 3: Check common WAF-specific paths ──
                waf_paths = [
                    ("/.well-known/security.txt", "security.txt"),
                    ("/cdn-cgi/trace", "Cloudflare"),
                ]
                for path, waf_hint in waf_paths:
                    try:
                        probe_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                        resp = await client.get(probe_url)
                        if resp.status_code == 200:
                            if waf_hint == "Cloudflare" and "fl=" in resp.text:
                                detected_wafs.setdefault("Cloudflare", []).append(
                                    f"CDN trace endpoint accessible at {probe_url}"
                                )
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        continue

        except Exception as e:
            logger.warning(f"WAF detection failed: {e}")
            return findings

        # ── Build findings from detections ──
        if detected_wafs:
            for waf_name, evidences in detected_wafs.items():
                confidence = "high" if len(evidences) >= 2 else "medium"
                unique_evidence = list(dict.fromkeys(evidences))  # dedupe, preserve order
                findings.append(
                    Finding(
                        title=f"WAF Detected: {waf_name}",
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        description=(
                            f"Web Application Firewall identified: {waf_name}. "
                            f"Confidence: {confidence}. "
                            f"This affects how other scans should be tuned to avoid false negatives."
                        ),
                        evidence="\n---\n".join(unique_evidence[:5]),
                        remediation="WAF presence is informational. Ensure WAF rules are up to date and in blocking mode.",
                        category="waf-detection",
                        references=[
                            "https://owasp.org/www-community/Web_Application_Firewall"
                        ],
                        metadata={
                            "waf_name": waf_name,
                            "confidence": confidence,
                            "evidence_count": len(unique_evidence),
                        },
                    )
                )
        else:
            findings.append(
                Finding(
                    title="No WAF Detected",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    description="No Web Application Firewall was detected. The application may be directly exposed.",
                    evidence=f"Target: {url}\nNo WAF signatures found in headers or blocking behavior.",
                    remediation="Consider deploying a WAF to provide an additional layer of defense.",
                    category="waf-detection",
                )
            )

        return findings

    def _check_headers(
        self, resp: httpx.Response, detected: dict[str, list[str]]
    ) -> None:
        """Check response headers for WAF fingerprints."""
        for header_name, value_substr, waf_name in WAF_HEADER_SIGNATURES:
            header_val = resp.headers.get(header_name, "")
            if not header_val:
                continue
            if not value_substr or value_substr.lower() in header_val.lower():
                evidence = f"Header: {header_name}: {header_val}"
                detected.setdefault(waf_name, []).append(evidence)

    def _check_body(
        self, body: str, detected: dict[str, list[str]], context: str
    ) -> None:
        """Check response body for WAF block-page signatures."""
        body_lower = body.lower()
        for pattern, waf_name in WAF_BODY_SIGNATURES:
            if pattern in body_lower:
                evidence = f"Body pattern: '{pattern}' found ({context})"
                detected.setdefault(waf_name, []).append(evidence)
