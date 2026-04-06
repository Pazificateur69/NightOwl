"""Email security configuration audit plugin.

Checks SPF, DKIM, and DMARC records for a target domain to identify
missing or weak email authentication configurations that could allow
spoofing and phishing attacks.
"""

import logging
import httpx
import re
from urllib.parse import urlparse

import dns.asyncresolver
import dns.name
import dns.resolver

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Common DKIM selectors used by major providers and default configurations
DKIM_SELECTORS = [
    "google",       # Google Workspace
    "default",      # Generic default
    "selector1",    # Microsoft 365
    "selector2",    # Microsoft 365
    "k1",           # Mailchimp
    "dkim",         # Generic
    "s1",           # Generic
    "s2",           # Generic
    "mail",         # Generic
    "mx",           # Generic
    "mandrill",     # Mailchimp/Mandrill
    "everlytickey1",  # Everlytic
    "cm",           # Campaign Monitor
    "protonmail",   # ProtonMail
    "smtp",         # Generic SMTP
]


class EmailSecurityPlugin(ScannerPlugin):
    """Audit email authentication (SPF, DKIM, DMARC) configuration."""

    name = "email-security"
    description = (
        "Check SPF, DKIM, and DMARC records for missing or weak "
        "email authentication configurations"
    )
    version = "1.0.0"
    stage = "scan"

    def _resolve_domain(self, target: Target) -> str | None:
        """Extract the domain from the target."""
        if target.domain:
            return target.domain
        if target.url:
            parsed = urlparse(target.url)
            return parsed.hostname
        host = target.host
        # Skip if it looks like a bare IP
        if not host.replace(".", "").isdigit():
            return host
        return None

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        domain = self._resolve_domain(target)

        if not domain:
            logger.warning(f"[{self.name}] Cannot determine domain for {target.host}")
            return findings

        try:
            # Check MX records first to confirm domain has mail
            mx_finding = await self._check_mx(domain)
            if mx_finding:
                findings.append(mx_finding)

            # Check SPF
            spf_findings = await self._check_spf(domain)
            findings.extend(spf_findings)

            # Check DKIM
            dkim_findings = await self._check_dkim(domain)
            findings.extend(dkim_findings)

            # Check DMARC
            dmarc_findings = await self._check_dmarc(domain)
            findings.extend(dmarc_findings)

        except Exception as e:
            logger.error(f"[{self.name}] {e}")

        return findings

    # ------------------------------------------------------------------
    # MX records
    # ------------------------------------------------------------------
    async def _check_mx(self, domain: str) -> Finding | None:
        """Check MX records to confirm mail services."""
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10
            answer = await resolver.resolve(domain, "MX")
            mx_records = sorted(
                [(rdata.preference, rdata.exchange.to_text().rstrip(".")) for rdata in answer],
                key=lambda x: x[0],
            )
            mx_list = "\n".join(f"  Priority {pref}: {exch}" for pref, exch in mx_records)

            return Finding(
                title=f"MX records found for {domain}",
                severity=Severity.INFO,
                description=f"Domain {domain} has {len(mx_records)} MX record(s) configured.",
                evidence=f"MX Records:\n{mx_list}",
                category="email-security",
                metadata={
                    "domain": domain,
                    "mx_records": [{"priority": p, "exchange": e} for p, e in mx_records],
                },
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return Finding(
                title=f"No MX records for {domain}",
                severity=Severity.INFO,
                description=f"No MX records found for {domain}. Domain may not handle email.",
                evidence=f"DNS MX query for {domain} returned no results",
                category="email-security",
                metadata={"domain": domain},
            )
        except Exception as e:
            logger.debug(f"[{self.name}] MX lookup error for {domain}: {e}")
            return None

    # ------------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------------
    async def _check_spf(self, domain: str) -> list[Finding]:
        """Check SPF record presence and configuration."""
        findings: list[Finding] = []

        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10
            answer = await resolver.resolve(domain, "TXT")
            txt_records = [rdata.to_text().strip('"') for rdata in answer]

            spf_records = [r for r in txt_records if r.startswith("v=spf1")]

            if not spf_records:
                findings.append(Finding(
                    title=f"No SPF record for {domain}",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        f"No SPF record found for {domain}. Without SPF, anyone can "
                        "send email pretending to be from this domain, enabling "
                        "phishing and spoofing attacks."
                    ),
                    evidence=f"DNS TXT query for {domain} contains no v=spf1 record",
                    remediation=(
                        "Add an SPF record. Example: v=spf1 include:_spf.google.com -all "
                        "(adjust for your mail providers)."
                    ),
                    category="email-security",
                    references=[
                        "https://tools.ietf.org/html/rfc7208",
                    ],
                    metadata={"domain": domain},
                ))
                return findings

            # Analyze SPF record
            spf = spf_records[0]
            findings.append(Finding(
                title=f"SPF record found for {domain}",
                severity=Severity.INFO,
                description=f"SPF record: {spf}",
                evidence=f"SPF: {spf}",
                category="email-security",
                metadata={"domain": domain, "spf": spf},
            ))

            # Check for +all (too permissive)
            if "+all" in spf:
                findings.append(Finding(
                    title=f"SPF record uses +all (permissive) for {domain}",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    description=(
                        f"The SPF record for {domain} uses '+all' which allows ANY "
                        "server to send email on behalf of this domain. This completely "
                        "negates the purpose of SPF."
                    ),
                    evidence=f"SPF: {spf}\n'+all' means all senders pass SPF check",
                    remediation=(
                        "Change '+all' to '-all' (hard fail) or '~all' (soft fail). "
                        "Only authorized senders should pass SPF."
                    ),
                    category="email-security",
                    metadata={"domain": domain, "spf": spf},
                ))

            # Check for ?all (neutral - weak)
            elif "?all" in spf:
                findings.append(Finding(
                    title=f"SPF record uses ?all (neutral) for {domain}",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        f"The SPF record for {domain} uses '?all' (neutral), which "
                        "does not enforce any policy for unauthorized senders."
                    ),
                    evidence=f"SPF: {spf}\n'?all' provides no enforcement",
                    remediation="Change '?all' to '-all' (hard fail) for proper enforcement.",
                    category="email-security",
                    metadata={"domain": domain, "spf": spf},
                ))

            # Check for ~all (softfail - acceptable but not ideal)
            elif "~all" in spf:
                findings.append(Finding(
                    title=f"SPF record uses ~all (softfail) for {domain}",
                    severity=Severity.LOW,
                    cvss_score=3.1,
                    description=(
                        f"The SPF record for {domain} uses '~all' (soft fail). While "
                        "common during migration, hard fail (-all) provides stronger "
                        "protection."
                    ),
                    evidence=f"SPF: {spf}\n'~all' marks unauthorized senders as softfail",
                    remediation=(
                        "Consider upgrading to '-all' (hard fail) once you've confirmed "
                        "all legitimate senders are included."
                    ),
                    category="email-security",
                    metadata={"domain": domain, "spf": spf},
                ))

            # Check for multiple SPF records (invalid per RFC)
            if len(spf_records) > 1:
                findings.append(Finding(
                    title=f"Multiple SPF records for {domain}",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        f"Domain {domain} has {len(spf_records)} SPF records. Per RFC 7208, "
                        "a domain must have at most one SPF record. Multiple records cause "
                        "unpredictable behavior."
                    ),
                    evidence=f"SPF records:\n" + "\n".join(spf_records),
                    remediation="Merge all SPF records into a single TXT record.",
                    category="email-security",
                    metadata={"domain": domain},
                ))

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append(Finding(
                title=f"No TXT records for {domain} (SPF missing)",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description=f"No TXT records found for {domain}, so no SPF is configured.",
                evidence=f"DNS TXT query for {domain} returned no results",
                remediation="Add an SPF record for the domain.",
                category="email-security",
            ))
        except Exception as e:
            logger.debug(f"[{self.name}] SPF lookup error for {domain}: {e}")

        return findings

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------
    async def _check_dkim(self, domain: str) -> list[Finding]:
        """Check DKIM configuration by querying common selectors."""
        findings: list[Finding] = []
        found_selectors: list[str] = []

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answer = await resolver.resolve(dkim_domain, "TXT")
                txt_records = [rdata.to_text().strip('"') for rdata in answer]
                dkim_records = [r for r in txt_records if "v=DKIM1" in r or "k=" in r or "p=" in r]
                if dkim_records:
                    found_selectors.append(selector)
                    # Check for empty public key (revoked)
                    for rec in dkim_records:
                        if "p=" in rec:
                            # Extract the p= value
                            p_match = re.search(r"p=([^;\s]*)", rec)
                            if p_match and not p_match.group(1):
                                findings.append(Finding(
                                    title=f"DKIM selector '{selector}' has empty public key (revoked)",
                                    severity=Severity.MEDIUM,
                                    cvss_score=5.3,
                                    description=(
                                        f"DKIM selector '{selector}' for {domain} has an empty "
                                        "public key, indicating the key has been revoked."
                                    ),
                                    evidence=f"DKIM record: {dkim_domain}\nRecord: {rec}",
                                    remediation="Remove revoked DKIM selectors or publish new keys.",
                                    category="email-security",
                                ))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        if found_selectors:
            findings.append(Finding(
                title=f"DKIM records found for {domain} ({len(found_selectors)} selector(s))",
                severity=Severity.INFO,
                description=(
                    f"DKIM is configured for {domain} with selectors: "
                    f"{', '.join(found_selectors)}"
                ),
                evidence=f"DKIM selectors found: {', '.join(found_selectors)}",
                category="email-security",
                metadata={"domain": domain, "dkim_selectors": found_selectors},
            ))
        else:
            findings.append(Finding(
                title=f"No DKIM records found for {domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description=(
                    f"No DKIM records found for {domain} across {len(DKIM_SELECTORS)} "
                    "common selectors. DKIM helps recipients verify that email "
                    "was sent by the domain owner and was not modified in transit."
                ),
                evidence=(
                    f"Checked selectors: {', '.join(DKIM_SELECTORS)}\n"
                    "None returned valid DKIM TXT records"
                ),
                remediation=(
                    "Configure DKIM signing for your email. Generate a key pair and "
                    "publish the public key as a TXT record under selector._domainkey.domain."
                ),
                category="email-security",
                references=[
                    "https://tools.ietf.org/html/rfc6376",
                ],
                metadata={"domain": domain},
            ))

        return findings

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------
    async def _check_dmarc(self, domain: str) -> list[Finding]:
        """Check DMARC record presence and policy."""
        findings: list[Finding] = []
        dmarc_domain = f"_dmarc.{domain}"

        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10
            answer = await resolver.resolve(dmarc_domain, "TXT")
            txt_records = [rdata.to_text().strip('"') for rdata in answer]

            dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

            if not dmarc_records:
                findings.append(Finding(
                    title=f"No DMARC record for {domain}",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        f"No DMARC record found at _dmarc.{domain}. Without DMARC, "
                        "receiving servers have no policy for handling SPF/DKIM failures, "
                        "leaving the domain vulnerable to spoofing."
                    ),
                    evidence=f"DNS TXT query for {dmarc_domain} has no v=DMARC1 record",
                    remediation=(
                        "Add a DMARC record. Start with: v=DMARC1; p=none; rua=mailto:dmarc@domain.com "
                        "then progress to p=quarantine and p=reject."
                    ),
                    category="email-security",
                    references=[
                        "https://tools.ietf.org/html/rfc7489",
                    ],
                    metadata={"domain": domain},
                ))
                return findings

            dmarc = dmarc_records[0]
            findings.append(Finding(
                title=f"DMARC record found for {domain}",
                severity=Severity.INFO,
                description=f"DMARC record: {dmarc}",
                evidence=f"DMARC: {dmarc}",
                category="email-security",
                metadata={"domain": domain, "dmarc": dmarc},
            ))

            # Parse policy
            policy_match = re.search(r"p=(none|quarantine|reject)", dmarc, re.IGNORECASE)
            if policy_match:
                policy = policy_match.group(1).lower()

                if policy == "none":
                    findings.append(Finding(
                        title=f"DMARC policy is 'none' (no enforcement) for {domain}",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description=(
                            f"The DMARC policy for {domain} is set to 'none', meaning "
                            "receiving servers will not take action on SPF/DKIM failures. "
                            "This provides monitoring but no protection against spoofing."
                        ),
                        evidence=f"DMARC: {dmarc}\nPolicy: p=none",
                        remediation=(
                            "Upgrade the DMARC policy to p=quarantine or p=reject after "
                            "reviewing DMARC aggregate reports to ensure legitimate email "
                            "passes authentication."
                        ),
                        category="email-security",
                        metadata={"domain": domain, "policy": policy},
                    ))

            # Check subdomain policy
            sp_match = re.search(r"sp=(none|quarantine|reject)", dmarc, re.IGNORECASE)
            if sp_match:
                sp_policy = sp_match.group(1).lower()
                if sp_policy == "none":
                    findings.append(Finding(
                        title=f"DMARC subdomain policy is 'none' for {domain}",
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        description=(
                            f"The DMARC subdomain policy (sp=) for {domain} is 'none'. "
                            "Subdomains can be spoofed even if the main domain has enforcement."
                        ),
                        evidence=f"DMARC: {dmarc}\nSubdomain policy: sp=none",
                        remediation="Set sp=quarantine or sp=reject to protect subdomains.",
                        category="email-security",
                    ))

            # Check percentage
            pct_match = re.search(r"pct=(\d+)", dmarc)
            if pct_match:
                pct = int(pct_match.group(1))
                if pct < 100:
                    findings.append(Finding(
                        title=f"DMARC percentage is {pct}% for {domain}",
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        description=(
                            f"DMARC policy applies to only {pct}% of messages. "
                            f"The remaining {100 - pct}% are unprotected."
                        ),
                        evidence=f"DMARC: {dmarc}\npct={pct}",
                        remediation="Increase pct to 100 for full coverage.",
                        category="email-security",
                    ))

            # Check for rua (aggregate reporting)
            if "rua=" not in dmarc:
                findings.append(Finding(
                    title=f"DMARC has no aggregate reporting (rua) for {domain}",
                    severity=Severity.LOW,
                    cvss_score=2.0,
                    description=(
                        "DMARC record does not specify an aggregate report address (rua). "
                        "Without reports, you cannot monitor authentication results."
                    ),
                    evidence=f"DMARC: {dmarc}\nNo rua= directive found",
                    remediation="Add rua=mailto:dmarc-reports@domain.com to receive aggregate reports.",
                    category="email-security",
                ))

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append(Finding(
                title=f"No DMARC record for {domain}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description=(
                    f"No DMARC record found at _dmarc.{domain}. The domain is "
                    "vulnerable to email spoofing and phishing attacks."
                ),
                evidence=f"DNS TXT query for {dmarc_domain} returned no results",
                remediation=(
                    "Add a DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com"
                ),
                category="email-security",
                metadata={"domain": domain},
            ))
        except Exception as e:
            logger.debug(f"[{self.name}] DMARC lookup error for {domain}: {e}")

        return findings
