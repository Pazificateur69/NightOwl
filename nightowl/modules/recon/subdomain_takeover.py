"""Subdomain takeover detection plugin."""

import logging

import httpx
import dns.resolver

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# CNAME -> service fingerprints that indicate potential takeover
TAKEOVER_SIGNATURES = {
    "amazonaws.com": {"service": "AWS S3", "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"]},
    "cloudfront.net": {"service": "AWS CloudFront", "fingerprint": ["Bad request", "ERROR: The request could not be satisfied"]},
    "herokuapp.com": {"service": "Heroku", "fingerprint": ["No such app", "no-such-app"]},
    "github.io": {"service": "GitHub Pages", "fingerprint": ["There isn't a GitHub Pages site here"]},
    "azurewebsites.net": {"service": "Azure", "fingerprint": ["404 Web Site not found"]},
    "cloudapp.azure.com": {"service": "Azure", "fingerprint": ["NXDOMAIN"]},
    "trafficmanager.net": {"service": "Azure Traffic Mgr", "fingerprint": ["NXDOMAIN"]},
    "blob.core.windows.net": {"service": "Azure Blob", "fingerprint": ["BlobNotFound", "The specified container does not exist"]},
    "shopify.com": {"service": "Shopify", "fingerprint": ["Sorry, this shop is currently unavailable"]},
    "pantheonsite.io": {"service": "Pantheon", "fingerprint": ["404 error unknown site"]},
    "zendesk.com": {"service": "Zendesk", "fingerprint": ["Help Center Closed"]},
    "wordpress.com": {"service": "WordPress", "fingerprint": ["Do you want to register"]},
    "ghost.io": {"service": "Ghost", "fingerprint": ["The thing you were looking for is no longer here"]},
    "surge.sh": {"service": "Surge.sh", "fingerprint": ["project not found"]},
    "bitbucket.io": {"service": "Bitbucket", "fingerprint": ["Repository not found"]},
    "smartling.com": {"service": "Smartling", "fingerprint": ["Domain is not configured"]},
    "acquia.com": {"service": "Acquia", "fingerprint": ["Web Site not found"]},
    "fastly.net": {"service": "Fastly", "fingerprint": ["Fastly error: unknown domain"]},
    "helpjuice.com": {"service": "HelpJuice", "fingerprint": ["We could not find what you're looking for"]},
    "helpscoutdocs.com": {"service": "HelpScout", "fingerprint": ["No settings were found"]},
    "feedpress.me": {"service": "FeedPress", "fingerprint": ["The feed has not been found"]},
    "freshdesk.com": {"service": "Freshdesk", "fingerprint": ["May not be configured"]},
    "unbounce.com": {"service": "Unbounce", "fingerprint": ["The requested URL was not found"]},
    "readme.io": {"service": "ReadMe", "fingerprint": ["Project doesnt exist"]},
    "tilda.ws": {"service": "Tilda", "fingerprint": ["Please renew your subscription"]},
}


class SubdomainTakeoverPlugin(ScannerPlugin):
    name = "subdomain-takeover"
    description = "Detect dangling DNS records vulnerable to subdomain takeover"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.domain or target.host

        # Get subdomains from previous findings metadata
        subdomains = kwargs.get("subdomains", [host])

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for subdomain in subdomains:
                await self._check_takeover(client, subdomain, findings)

        return findings

    async def _check_takeover(self, client, subdomain, findings):
        # Resolve CNAME
        cname = None
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                cname = str(rdata.target).rstrip(".")
        except Exception:
            return

        if not cname:
            return

        # Check against known vulnerable services
        for pattern, info in TAKEOVER_SIGNATURES.items():
            if pattern in cname:
                try:
                    resp = await client.get(f"https://{subdomain}")
                    body = resp.text

                    for fp in info["fingerprint"]:
                        if fp.lower() in body.lower() or fp == "NXDOMAIN":
                            findings.append(Finding(
                                title=f"Subdomain takeover: {subdomain} -> {info['service']}",
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                description=f"Subdomain {subdomain} points to {cname} ({info['service']}) which is unclaimed and can be taken over",
                                evidence=f"Subdomain: {subdomain}\nCNAME: {cname}\nService: {info['service']}\nFingerprint: {fp}\nStatus: {resp.status_code}",
                                remediation=f"Remove the dangling DNS record for {subdomain}, or claim the resource on {info['service']}.",
                                category="subdomain-takeover",
                                references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                                metadata={"cname": cname, "service": info["service"]},
                            ))
                            return
                except Exception:
                    pass
