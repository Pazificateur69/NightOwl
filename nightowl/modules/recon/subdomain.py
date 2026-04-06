"""Subdomain enumeration plugin for NightOwl recon stage.

Brute-forces subdomains against a target domain using async DNS resolution
with configurable rate limiting.
"""

import asyncio
import logging
from pathlib import Path

import dns.asyncresolver
import dns.resolver

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target
from nightowl.utils.rate_limiter import RateLimiter

logger = logging.getLogger("nightowl")

# Compact default wordlist used when no external file is supplied.
_DEFAULT_SUBDOMAINS: list[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "staging",
    "test", "api", "app", "admin", "portal", "vpn", "remote", "gateway",
    "proxy", "cdn", "cloud", "media", "static", "assets", "img", "images",
    "docs", "wiki", "support", "help", "status", "monitor", "git", "gitlab",
    "github", "jenkins", "ci", "cd", "build", "deploy", "prod", "production",
    "uat", "qa", "sandbox", "demo", "beta", "alpha", "stage", "stg", "dr",
    "backup", "bak", "old", "new", "web", "web1", "web2", "db", "database",
    "sql", "mysql", "postgres", "redis", "elastic", "search", "es", "kibana",
    "grafana", "prometheus", "vault", "consul", "k8s", "kubernetes", "docker",
    "registry", "harbor", "nexus", "artifactory", "jira", "confluence",
    "bitbucket", "slack", "teams", "zoom", "meet", "chat", "irc",
    "shop", "store", "pay", "payment", "billing", "invoice", "crm",
    "erp", "sso", "auth", "login", "id", "identity", "oauth", "oidc",
    "internal", "intranet", "extranet", "partner", "vendor", "client",
    "m", "mobile", "ws", "websocket", "graphql", "rest", "v1", "v2",
]


class SubdomainPlugin(ScannerPlugin):
    """Enumerate subdomains via async DNS brute-force."""

    name = "subdomain-enum"
    description = "Brute-force subdomain discovery using DNS resolution with rate limiting"
    version = "1.0.0"
    stage = "recon"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self._wordlist_path: str | None = self.config.get("wordlist")
        self._concurrency: int = self.config.get("concurrency", 50)
        self._timeout: float = self.config.get("timeout", 3.0)
        self._rate: float = self.config.get("rate", 100.0)
        self._burst: int = self.config.get("burst", 200)
        self._nameservers: list[str] | None = self.config.get("nameservers")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def run(self, target: Target, **kwargs) -> list[Finding]:
        domain = self._resolve_domain(target)
        if not domain:
            logger.warning(f"[{self.name}] Cannot determine domain for {target.host}")
            return []

        wordlist = self._load_wordlist()
        logger.info(
            f"[{self.name}] Enumerating subdomains of {domain} "
            f"({len(wordlist)} candidates, concurrency={self._concurrency})"
        )

        discovered: list[dict] = []
        semaphore = asyncio.Semaphore(self._concurrency)
        limiter = RateLimiter(rate=self._rate, burst=self._burst)

        async def _check(sub: str) -> None:
            fqdn = f"{sub}.{domain}"
            async with semaphore:
                await limiter.acquire()
                try:
                    result = await self._resolve(fqdn)
                    if result:
                        discovered.append({"subdomain": fqdn, "addresses": result})
                        logger.debug(f"[{self.name}] Found: {fqdn} -> {', '.join(result)}")
                finally:
                    limiter.release()

        tasks = [_check(word) for word in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

        if not discovered:
            return [
                Finding(
                    title=f"No subdomains discovered for {domain}",
                    description=f"Tested {len(wordlist)} candidates; none resolved.",
                    severity=Severity.INFO,
                    category="subdomain-enum",
                    metadata={"domain": domain, "candidates_tested": len(wordlist)},
                )
            ]

        findings: list[Finding] = []

        # Individual finding per subdomain
        for entry in discovered:
            findings.append(
                Finding(
                    title=f"Subdomain discovered: {entry['subdomain']}",
                    description=(
                        f"The subdomain {entry['subdomain']} resolves to "
                        f"{', '.join(entry['addresses'])}."
                    ),
                    severity=Severity.INFO,
                    category="subdomain-enum",
                    evidence=f"{entry['subdomain']} -> {', '.join(entry['addresses'])}",
                    metadata=entry,
                )
            )

        # Summary finding
        findings.append(
            Finding(
                title=f"Subdomain enumeration summary for {domain}",
                description=(
                    f"Discovered {len(discovered)} subdomain(s) out of "
                    f"{len(wordlist)} candidates tested."
                ),
                severity=Severity.INFO,
                category="subdomain-enum",
                evidence="\n".join(
                    f"{e['subdomain']} -> {', '.join(e['addresses'])}"
                    for e in discovered
                ),
                metadata={
                    "domain": domain,
                    "total_found": len(discovered),
                    "candidates_tested": len(wordlist),
                    "subdomains": [e["subdomain"] for e in discovered],
                },
            )
        )

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _resolve_domain(self, target: Target) -> str | None:
        if target.domain:
            return target.domain
        if target.url:
            from urllib.parse import urlparse

            return urlparse(target.url).hostname
        host = target.host
        if not host.replace(".", "").isdigit():
            return host
        return None

    def _load_wordlist(self) -> list[str]:
        """Load subdomain wordlist from file or use default."""
        if self._wordlist_path:
            path = Path(self._wordlist_path)
            if path.is_file():
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                    words = [
                        line.strip()
                        for line in text.splitlines()
                        if line.strip() and not line.startswith("#")
                    ]
                    if words:
                        logger.info(
                            f"[{self.name}] Loaded {len(words)} words from {path}"
                        )
                        return words
                except OSError as exc:
                    logger.warning(
                        f"[{self.name}] Failed to read wordlist {path}: {exc}"
                    )
            else:
                logger.warning(
                    f"[{self.name}] Wordlist not found: {path}, using defaults"
                )

        return list(_DEFAULT_SUBDOMAINS)

    async def _resolve(self, fqdn: str) -> list[str] | None:
        """Attempt to resolve *fqdn* to A records. Returns IPs or None."""
        resolver = dns.asyncresolver.Resolver()
        if self._nameservers:
            resolver.nameservers = self._nameservers
        resolver.lifetime = self._timeout

        try:
            answer = await resolver.resolve(fqdn, "A")
            return [rdata.to_text() for rdata in answer]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.name.EmptyLabel,
            Exception,
        ):
            return None
