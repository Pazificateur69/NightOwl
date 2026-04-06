"""HTTP request smuggling detection plugin.

Detects HTTP request smuggling vulnerabilities by sending ambiguous requests
with conflicting Content-Length and Transfer-Encoding headers (CL.TE and TE.CL
variants) and analyzing response desynchronization via timing analysis.
"""

import logging
import time
from urllib.parse import urlparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Transfer-Encoding obfuscation variants
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: \tchunked",
    " Transfer-Encoding: chunked",
    "X: X\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding\r\n: chunked",
]


class HTTPSmugglingPlugin(ScannerPlugin):
    name = "http-smuggling"
    description = "Detect HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, CL.0)"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=False,
                timeout=15,
                http2=False,  # Smuggling only applies to HTTP/1.1
            ) as client:
                # ── Phase 1: Detect Transfer-Encoding handling ──
                te_findings = await self._test_te_handling(client, url, host)
                findings.extend(te_findings)

                # ── Phase 2: CL.TE detection via timing ──
                clte_finding = await self._test_clte_timing(
                    client, base_url, path, host
                )
                if clte_finding:
                    findings.append(clte_finding)

                # ── Phase 3: TE.CL detection via timing ──
                tecl_finding = await self._test_tecl_timing(
                    client, base_url, path, host
                )
                if tecl_finding:
                    findings.append(tecl_finding)

                # ── Phase 4: TE.TE obfuscation detection ──
                tete_findings = await self._test_te_obfuscation(
                    client, url, host
                )
                findings.extend(tete_findings)

                # ── Phase 5: CL.0 detection ──
                cl0_finding = await self._test_cl_zero(client, url)
                if cl0_finding:
                    findings.append(cl0_finding)

        except Exception as e:
            logger.warning(f"HTTP smuggling scan failed: {e}")

        return findings

    async def _test_te_handling(
        self, client: httpx.AsyncClient, url: str, host: str
    ) -> list[Finding]:
        """Check how the server handles Transfer-Encoding headers."""
        findings: list[Finding] = []

        # Test if server accepts chunked encoding
        chunked_body = "1\r\nZ\r\n0\r\n\r\n"
        try:
            resp = await client.post(
                url,
                content=chunked_body,
                headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            self._chunked_baseline = resp.status_code
        except Exception as e:
            logger.debug(f"TE handling test failed: {e}")
            self._chunked_baseline = None

        # Test conflicting CL and TE
        try:
            resp = await client.post(
                url,
                content="0\r\n\r\n",
                headers={
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            if resp.status_code < 500:
                findings.append(
                    Finding(
                        title="Server Accepts Conflicting CL/TE Headers",
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        description=(
                            "The server processes requests with both Content-Length and "
                            "Transfer-Encoding headers without rejecting them. "
                            "This is a prerequisite for HTTP request smuggling."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Both CL and TE headers were accepted"
                        ),
                        remediation=(
                            "Configure the server/proxy to reject requests with "
                            "both Content-Length and Transfer-Encoding headers."
                        ),
                        category="http-smuggling",
                    )
                )
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return findings

    async def _test_clte_timing(
        self, client: httpx.AsyncClient, base_url: str, path: str, host: str
    ) -> Finding | None:
        """
        Detect CL.TE smuggling via timing difference.

        Send a request where:
        - CL indicates the entire body has been sent
        - TE (chunked) expects more data, causing the back-end to wait/timeout
        """
        # Normal request timing baseline
        try:
            start = time.time()
            await client.post(
                f"{base_url}{path}",
                content="x=1",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            baseline_time = time.time() - start
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            baseline_time = 1.0

        # CL.TE probe: CL says body is short, but chunked encoding is incomplete
        smuggle_body = "1\r\nZ\r\nQ"  # Incomplete chunked body
        try:
            start = time.time()
            resp = await client.post(
                f"{base_url}{path}",
                content=smuggle_body,
                headers={
                    "Content-Length": str(len(smuggle_body)),
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            probe_time = time.time() - start

            # If the probe takes significantly longer, the back-end may be
            # using TE and waiting for the complete chunked body
            if probe_time > baseline_time + 5:
                return Finding(
                    title="Potential CL.TE HTTP Request Smuggling",
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    description=(
                        "Timing analysis suggests CL.TE HTTP request smuggling vulnerability. "
                        "The front-end uses Content-Length and the back-end uses Transfer-Encoding. "
                        "This allows an attacker to smuggle requests to the back-end, "
                        "potentially bypassing security controls, poisoning caches, "
                        "or hijacking other users' requests."
                    ),
                    evidence=(
                        f"URL: {base_url}{path}\n"
                        f"Baseline time: {baseline_time:.2f}s\n"
                        f"Probe time: {probe_time:.2f}s\n"
                        f"Delta: {probe_time - baseline_time:.2f}s\n"
                        f"Response status: {resp.status_code}"
                    ),
                    remediation=(
                        "Normalize request parsing between front-end and back-end. "
                        "Use HTTP/2 end-to-end. Reject ambiguous requests with both CL and TE. "
                        "Configure the front-end to normalize chunked encoding."
                    ),
                    category="http-smuggling",
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                        "https://cwe.mitre.org/data/definitions/444.html",
                    ],
                    metadata={"type": "CL.TE", "timing_delta": probe_time - baseline_time},
                )

        except httpx.ReadTimeout:
            return Finding(
                title="Potential CL.TE HTTP Request Smuggling (Timeout)",
                severity=Severity.HIGH,
                cvss_score=8.1,
                description=(
                    "CL.TE smuggling probe caused a timeout, suggesting the back-end "
                    "is waiting for chunked transfer completion while the front-end "
                    "used Content-Length."
                ),
                evidence=(
                    f"URL: {base_url}{path}\n"
                    f"Baseline time: {baseline_time:.2f}s\n"
                    f"Probe result: Timeout\n"
                    f"Probe type: Incomplete chunked body with valid CL"
                ),
                remediation=(
                    "Normalize request parsing. Use HTTP/2. Reject ambiguous requests."
                ),
                category="http-smuggling",
                references=[
                    "https://portswigger.net/web-security/request-smuggling",
                ],
                metadata={"type": "CL.TE"},
            )
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return None

    async def _test_tecl_timing(
        self, client: httpx.AsyncClient, base_url: str, path: str, host: str
    ) -> Finding | None:
        """
        Detect TE.CL smuggling via timing.

        Send a request where:
        - TE indicates the body is complete (proper chunked termination)
        - CL is larger than actual body, causing back-end to wait for more data
        """
        try:
            start = time.time()
            await client.post(
                f"{base_url}{path}",
                content="x=1",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            baseline_time = time.time() - start
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            baseline_time = 1.0

        # TE.CL probe: chunked body is complete (0\r\n\r\n) but CL is much larger
        smuggle_body = "0\r\n\r\n"
        try:
            start = time.time()
            resp = await client.post(
                f"{base_url}{path}",
                content=smuggle_body,
                headers={
                    "Content-Length": "100",
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            probe_time = time.time() - start

            if probe_time > baseline_time + 5:
                return Finding(
                    title="Potential TE.CL HTTP Request Smuggling",
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    description=(
                        "Timing analysis suggests TE.CL HTTP request smuggling vulnerability. "
                        "The front-end uses Transfer-Encoding and the back-end uses Content-Length."
                    ),
                    evidence=(
                        f"URL: {base_url}{path}\n"
                        f"Baseline time: {baseline_time:.2f}s\n"
                        f"Probe time: {probe_time:.2f}s\n"
                        f"Delta: {probe_time - baseline_time:.2f}s\n"
                        f"Response status: {resp.status_code}"
                    ),
                    remediation=(
                        "Normalize request parsing between front-end and back-end. "
                        "Use HTTP/2 end-to-end. Reject ambiguous requests."
                    ),
                    category="http-smuggling",
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                    ],
                    metadata={"type": "TE.CL", "timing_delta": probe_time - baseline_time},
                )

        except httpx.ReadTimeout:
            return Finding(
                title="Potential TE.CL HTTP Request Smuggling (Timeout)",
                severity=Severity.HIGH,
                cvss_score=8.1,
                description=(
                    "TE.CL smuggling probe caused a timeout, suggesting the back-end "
                    "is waiting for more data based on Content-Length."
                ),
                evidence=(
                    f"URL: {base_url}{path}\n"
                    f"Probe type: Complete chunked body with oversized CL"
                ),
                remediation="Normalize request parsing. Use HTTP/2. Reject ambiguous requests.",
                category="http-smuggling",
                metadata={"type": "TE.CL"},
            )
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return None

    async def _test_te_obfuscation(
        self, client: httpx.AsyncClient, url: str, host: str
    ) -> list[Finding]:
        """Test Transfer-Encoding header obfuscation variants."""
        findings: list[Finding] = []

        # Get baseline response
        try:
            baseline = await client.post(
                url,
                content="0\r\n\r\n",
                headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            baseline_status = baseline.status_code
            baseline_len = len(baseline.text)
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            return findings

        inconsistent_tes: list[str] = []

        for te_variant in TE_OBFUSCATIONS:
            parts = te_variant.split(": ", 1)
            header_name = parts[0].strip() if len(parts) == 2 else "Transfer-Encoding"
            header_value = parts[1].strip() if len(parts) == 2 else "chunked"
            try:
                resp = await client.post(
                    url,
                    content="0\r\n\r\n",
                    headers={
                        header_name: header_value,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

                # If the obfuscated TE produces a different response, the servers
                # may disagree on how to parse the header
                if (
                    resp.status_code != baseline_status
                    or abs(len(resp.text) - baseline_len) > 100
                ):
                    inconsistent_tes.append(te_variant)

            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        if inconsistent_tes:
            findings.append(
                Finding(
                    title="Transfer-Encoding Obfuscation Inconsistency",
                    severity=Severity.MEDIUM,
                    cvss_score=5.9,
                    description=(
                        "The server responds differently to obfuscated Transfer-Encoding headers. "
                        "This suggests front-end and back-end may disagree on TE parsing, "
                        "which is a prerequisite for TE.TE smuggling."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Baseline: status={baseline_status}, length={baseline_len}\n"
                        f"Inconsistent TE variants ({len(inconsistent_tes)}):\n"
                        + "\n".join(f"  - {v}" for v in inconsistent_tes[:5])
                    ),
                    remediation=(
                        "Normalize Transfer-Encoding header processing. "
                        "Reject requests with malformed TE headers."
                    ),
                    category="http-smuggling",
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                    ],
                    metadata={"type": "TE.TE"},
                )
            )

        return findings

    async def _test_cl_zero(
        self, client: httpx.AsyncClient, url: str
    ) -> Finding | None:
        """Test for CL.0 smuggling (back-end ignores Content-Length: 0)."""
        try:
            # Send request with CL: 0 but no body
            resp_normal = await client.post(
                url,
                content="",
                headers={
                    "Content-Length": "0",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # Send request with CL: 0 but include a body
            resp_with_body = await client.post(
                url,
                content="nightowl_smuggle_test=1",
                headers={
                    "Content-Length": "0",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # If responses differ significantly, the body was processed despite CL: 0
            if (
                resp_with_body.status_code != resp_normal.status_code
                or abs(len(resp_with_body.text) - len(resp_normal.text)) > 50
            ):
                return Finding(
                    title="Potential CL.0 HTTP Request Smuggling",
                    severity=Severity.MEDIUM,
                    cvss_score=5.9,
                    description=(
                        "The server appears to process request body data despite "
                        "Content-Length: 0. This may enable CL.0 request smuggling."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"CL:0 empty: status={resp_normal.status_code}, length={len(resp_normal.text)}\n"
                        f"CL:0 with body: status={resp_with_body.status_code}, length={len(resp_with_body.text)}"
                    ),
                    remediation=(
                        "Ensure the server strictly honors Content-Length. "
                        "Reject requests where body size doesn't match CL."
                    ),
                    category="http-smuggling",
                    metadata={"type": "CL.0"},
                )

        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return None
