"""DNS enumeration plugin for NightOwl recon stage.

Resolves multiple DNS record types and attempts zone transfers
to discover as much information about a target domain as possible.
"""

import asyncio
import logging
from typing import Any

import dns.asyncresolver
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")


class DNSEnumPlugin(ScannerPlugin):
    """Enumerate DNS records and attempt zone transfers."""

    name = "dns-enum"
    description = "Resolves DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME) and attempts AXFR zone transfer"
    version = "1.0.0"
    stage = "recon"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self._timeout: float = self.config.get("timeout", 5.0)
        self._nameservers: list[str] | None = self.config.get("nameservers")
        self._record_types: list[str] = self.config.get("record_types", list(_RECORD_TYPES))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def run(self, target: Target, **kwargs) -> list[Finding]:
        domain = self._resolve_domain(target)
        if not domain:
            logger.warning(f"[{self.name}] Cannot determine domain for {target.host}")
            return []

        findings: list[Finding] = []

        # Resolve standard record types in parallel
        tasks = [self._query_records(domain, rtype) for rtype in self._record_types]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_records: dict[str, list[str]] = {}
        for rtype, result in zip(self._record_types, results):
            if isinstance(result, Exception):
                logger.debug(f"[{self.name}] {rtype} query failed for {domain}: {result}")
                continue
            if result:
                all_records[rtype] = result

        # Build findings per record type
        for rtype, records in all_records.items():
            findings.append(self._make_record_finding(domain, rtype, records))

        # Emit a combined summary if we found anything
        if all_records:
            findings.append(
                Finding(
                    title=f"DNS enumeration summary for {domain}",
                    description=self._format_summary(domain, all_records),
                    severity=Severity.INFO,
                    category="dns-enum",
                    evidence="\n".join(
                        f"{rt}: {', '.join(recs)}" for rt, recs in all_records.items()
                    ),
                    metadata={"domain": domain, "records": all_records},
                )
            )

        # Attempt zone transfer
        axfr_findings = await self._attempt_zone_transfer(domain, all_records.get("NS", []))
        findings.extend(axfr_findings)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _resolve_domain(self, target: Target) -> str | None:
        """Extract the domain string from the target."""
        if target.domain:
            return target.domain
        if target.url:
            from urllib.parse import urlparse

            parsed = urlparse(target.url)
            return parsed.hostname
        # Fallback: if host looks like a domain, use it directly
        host = target.host
        if not host.replace(".", "").isdigit():
            return host
        return None

    async def _query_records(self, domain: str, rtype: str) -> list[str]:
        """Asynchronously resolve *rtype* records for *domain*."""
        resolver = dns.asyncresolver.Resolver()
        if self._nameservers:
            resolver.nameservers = self._nameservers
        resolver.lifetime = self._timeout

        try:
            answer = await resolver.resolve(domain, rtype)
            return [rdata.to_text() for rdata in answer]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.asyncresolver.NoAnswer,
            dns.name.EmptyLabel,
            Exception,
        ):
            return []

    async def _attempt_zone_transfer(
        self, domain: str, nameservers: list[str]
    ) -> list[Finding]:
        """Try an AXFR zone transfer against each discovered NS."""
        findings: list[Finding] = []

        if not nameservers:
            # Try to resolve NS ourselves
            try:
                resolver = dns.asyncresolver.Resolver()
                if self._nameservers:
                    resolver.nameservers = self._nameservers
                resolver.lifetime = self._timeout
                answer = await resolver.resolve(domain, "NS")
                nameservers = [rdata.to_text().rstrip(".") for rdata in answer]
            except (OSError, RuntimeError, ValueError, Exception) as exc:
                logger.debug(f"Error: {exc}")
                return findings

        for ns in nameservers:
            ns_clean = ns.rstrip(".")
            try:
                # dns.query.xfr is synchronous; run in thread
                records = await asyncio.to_thread(self._do_axfr, domain, ns_clean)
                if records:
                    findings.append(
                        Finding(
                            title=f"Zone transfer (AXFR) successful on {ns_clean}",
                            description=(
                                f"The nameserver {ns_clean} allows unrestricted zone transfers "
                                f"for {domain}. This exposes all DNS records to any requester."
                            ),
                            severity=Severity.HIGH,
                            cvss_score=5.3,
                            category="dns-zone-transfer",
                            evidence="\n".join(records[:50]),  # cap evidence size
                            remediation=(
                                "Restrict AXFR to authorised secondary nameservers using "
                                "allow-transfer ACLs in your DNS server configuration."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"
                            ],
                            metadata={
                                "nameserver": ns_clean,
                                "domain": domain,
                                "record_count": len(records),
                            },
                        )
                    )
            except Exception as exc:
                logger.debug(
                    f"[{self.name}] AXFR failed on {ns_clean} for {domain}: {exc}"
                )

        return findings

    @staticmethod
    def _do_axfr(domain: str, nameserver: str) -> list[str]:
        """Perform a synchronous zone transfer and return record lines."""
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, lifetime=10))
            records: list[str] = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name} {rdataset.ttl} {rdataset.rdclass.name} {rdataset.rdtype.name} {rdata.to_text()}")
            return records
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            return []

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------
    @staticmethod
    def _make_record_finding(domain: str, rtype: str, records: list[str]) -> Finding:
        return Finding(
            title=f"DNS {rtype} records for {domain}",
            description=f"Resolved {len(records)} {rtype} record(s) for {domain}.",
            severity=Severity.INFO,
            category="dns-records",
            evidence="\n".join(records),
            metadata={"domain": domain, "record_type": rtype, "records": records},
        )

    @staticmethod
    def _format_summary(domain: str, records: dict[str, list[str]]) -> str:
        lines = [f"DNS enumeration results for {domain}:"]
        for rtype, recs in records.items():
            lines.append(f"  {rtype}: {len(recs)} record(s)")
            for r in recs:
                lines.append(f"    - {r}")
        return "\n".join(lines)
