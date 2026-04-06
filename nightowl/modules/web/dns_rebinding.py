"""DNS rebinding vulnerability scanner plugin.

Checks whether a target validates the Host header and whether DNS
records have suspiciously low TTLs, both of which are indicators
of susceptibility to DNS rebinding attacks.
"""

import hashlib
import logging
from urllib.parse import urlparse

import dns.asyncresolver
import dns.resolver
import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Host header values that simulate rebinding to internal addresses
REBINDING_HOSTS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "169.254.169.254",      # AWS metadata
    "[::1]",                 # IPv6 loopback
]

# Threshold in seconds below which TTL is considered suspiciously low
LOW_TTL_THRESHOLD = 60


class DNSRebindingPlugin(ScannerPlugin):
    """Detect DNS rebinding vulnerabilities via Host header tests and TTL analysis."""

    name = "dns-rebinding"
    description = (
        "Check for DNS rebinding vulnerability by testing Host header "
        "validation and analysing DNS TTL values"
    )
    version = "1.0.0"
    stage = "scan"

    def _resolve_base_url(self, target: Target) -> str:
        if target.url:
            return target.url.rstrip("/")
        scheme = "https" if target.port in (443, 8443, None) else "http"
        host = target.domain or target.ip or target.host
        port_part = "" if target.port in (80, 443, None) else f":{target.port}"
        return f"{scheme}://{host}{port_part}"

    def _resolve_domain(self, target: Target) -> str | None:
        if target.domain:
            return target.domain
        if target.url:
            parsed = urlparse(target.url)
            hostname = parsed.hostname
            # Only return if it looks like a domain (not an IP)
            if hostname and not hostname.replace(".", "").isdigit():
                return hostname
        host = target.host
        if not host.replace(".", "").isdigit():
            return host
        return None

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        base_url = self._resolve_base_url(target)
        domain = self._resolve_domain(target)

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=10
            ) as client:
                # Step 1: Host header validation tests
                host_findings = await self._test_host_header_validation(
                    client, base_url, target
                )
                findings.extend(host_findings)

            # Step 2: DNS TTL analysis (independent of HTTP client)
            if domain:
                ttl_findings = await self._check_dns_ttl(domain)
                findings.extend(ttl_findings)

        except Exception as e:
            logger.error(f"[{self.name}] {e}")

        return findings

    # ------------------------------------------------------------------
    # Host header validation
    # ------------------------------------------------------------------
    async def _test_host_header_validation(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        target: Target,
    ) -> list[Finding]:
        """Send requests with different Host headers and compare responses."""
        findings: list[Finding] = []

        # First, get the baseline response with the legitimate host
        try:
            baseline_resp = await client.get(base_url)
            baseline_hash = self._content_hash(baseline_resp.text)
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_resp.content)
        except httpx.RequestError as exc:
            logger.warning(f"[{self.name}] Cannot reach {base_url}: {exc}")
            return findings

        # Track which rebinding hosts produced matching responses
        matching_hosts: list[dict] = []
        rejected_hosts: list[str] = []

        for fake_host in REBINDING_HOSTS:
            try:
                resp = await client.get(
                    base_url,
                    headers={"Host": fake_host},
                )
                resp_hash = self._content_hash(resp.text)
                resp_status = resp.status_code
                resp_length = len(resp.content)

                # Compare: same content hash + same status code = no validation
                if resp_hash == baseline_hash and resp_status == baseline_status:
                    matching_hosts.append({
                        "host": fake_host,
                        "status": resp_status,
                        "length": resp_length,
                    })
                elif resp_status in (400, 403, 421):
                    # Server explicitly rejected the mismatched host
                    rejected_hosts.append(fake_host)
                elif resp_status == baseline_status and self._similar_length(baseline_length, resp_length):
                    # Status matches and content length is very similar -
                    # still likely vulnerable even if body changed slightly
                    matching_hosts.append({
                        "host": fake_host,
                        "status": resp_status,
                        "length": resp_length,
                    })

            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        if matching_hosts:
            host_list = "\n".join(
                f"  Host: {m['host']} -> HTTP {m['status']} ({m['length']} bytes)"
                for m in matching_hosts
            )
            # Determine severity based on which hosts matched
            has_metadata_ip = any(
                m["host"] == "169.254.169.254" for m in matching_hosts
            )
            has_internal = any(
                m["host"] in ("127.0.0.1", "localhost", "0.0.0.0", "[::1]")
                for m in matching_hosts
            )

            if has_metadata_ip:
                severity = Severity.HIGH
                cvss = 8.6
            elif has_internal:
                severity = Severity.HIGH
                cvss = 7.5
            else:
                severity = Severity.MEDIUM
                cvss = 5.3

            findings.append(Finding(
                title=f"Weak Host header validation ({len(matching_hosts)} accepted)",
                severity=severity,
                cvss_score=cvss,
                description=(
                    "The server accepts requests with arbitrary Host header values "
                    "and returns the same content as the legitimate request. This "
                    "indicates the application does not validate the Host header, "
                    "making it potentially vulnerable to DNS rebinding attacks. "
                    "An attacker could bind a malicious domain to the server's IP, "
                    "then rebind to an internal address to access internal services "
                    "from the victim's browser."
                ),
                evidence=(
                    f"Baseline: {base_url} -> HTTP {baseline_status} "
                    f"({baseline_length} bytes)\n"
                    f"Matching responses with fake Host headers:\n{host_list}"
                ),
                remediation=(
                    "Validate the Host header against a whitelist of expected values. "
                    "Return HTTP 421 Misdirected Request for unrecognized hosts. "
                    "In web frameworks, configure ALLOWED_HOSTS (Django), "
                    "server_name (Nginx), or equivalent."
                ),
                category="dns-rebinding",
                references=[
                    "https://owasp.org/www-community/attacks/DNS_Rebinding",
                ],
                metadata={
                    "matching_hosts": matching_hosts,
                    "rejected_hosts": rejected_hosts,
                },
            ))

        elif rejected_hosts:
            findings.append(Finding(
                title="Host header validation appears active",
                severity=Severity.INFO,
                description=(
                    "The server rejects requests with mismatched Host headers, "
                    "indicating DNS rebinding protection is in place."
                ),
                evidence=(
                    f"Rejected Host headers ({len(rejected_hosts)}):\n"
                    + "\n".join(f"  {h}" for h in rejected_hosts)
                ),
                category="dns-rebinding",
            ))

        return findings

    # ------------------------------------------------------------------
    # DNS TTL analysis
    # ------------------------------------------------------------------
    async def _check_dns_ttl(self, domain: str) -> list[Finding]:
        """Check if DNS records have suspiciously low TTLs."""
        findings: list[Finding] = []

        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10

            for rtype in ("A", "AAAA"):
                try:
                    answer = await resolver.resolve(domain, rtype)
                    ttl = answer.rrset.ttl if answer.rrset else None

                    if ttl is not None and ttl < LOW_TTL_THRESHOLD:
                        records = [rdata.to_text() for rdata in answer]
                        findings.append(Finding(
                            title=f"Suspiciously low DNS TTL for {domain} ({rtype}: {ttl}s)",
                            severity=Severity.MEDIUM,
                            cvss_score=4.3,
                            description=(
                                f"The DNS {rtype} record for {domain} has a TTL of {ttl} "
                                f"seconds (threshold: {LOW_TTL_THRESHOLD}s). Very low TTLs "
                                "can facilitate DNS rebinding attacks by allowing rapid "
                                "re-resolution to different IP addresses. Low TTL alone is "
                                "not a vulnerability but combined with weak Host header "
                                "validation it increases risk."
                            ),
                            evidence=(
                                f"Domain: {domain}\n"
                                f"Record type: {rtype}\n"
                                f"TTL: {ttl} seconds\n"
                                f"Records: {', '.join(records)}"
                            ),
                            remediation=(
                                "If the low TTL is not intentional (e.g., for failover), "
                                "increase it to at least 300 seconds. Ensure the application "
                                "validates Host headers regardless of DNS TTL."
                            ),
                            category="dns-rebinding",
                            metadata={
                                "domain": domain,
                                "record_type": rtype,
                                "ttl": ttl,
                                "records": records,
                            },
                        ))
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

        except Exception as e:
            logger.debug(f"[{self.name}] DNS TTL check error for {domain}: {e}")

        return findings

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    @staticmethod
    def _content_hash(content: str) -> str:
        """Produce a hash of the response body for comparison."""
        return hashlib.sha256(content.encode(errors="replace")).hexdigest()

    @staticmethod
    def _similar_length(len_a: int, len_b: int, tolerance: float = 0.05) -> bool:
        """Check if two content lengths are within tolerance of each other."""
        if len_a == 0 and len_b == 0:
            return True
        if len_a == 0 or len_b == 0:
            return False
        ratio = abs(len_a - len_b) / max(len_a, len_b)
        return ratio <= tolerance
