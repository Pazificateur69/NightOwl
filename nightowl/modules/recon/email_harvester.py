"""Email and contact information harvester."""

import logging
import re

import httpx
from bs4 import BeautifulSoup

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

SEARCH_PATHS = [
    "/", "/about", "/contact", "/team", "/about-us", "/contact-us",
    "/people", "/staff", "/leadership", "/our-team", "/humans.txt",
    "/sitemap.xml", "/robots.txt",
]


class EmailHarvesterPlugin(ScannerPlugin):
    name = "email-harvester"
    description = "Harvest email addresses and contact info from target website"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = target.url or f"https://{target.host}"
        domain = target.domain or target.host
        emails = set()
        phones = set()
        socials = set()

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                for path in SEARCH_PATHS:
                    try:
                        resp = await client.get(f"{base_url.rstrip('/')}{path}")
                        if resp.status_code != 200:
                            continue

                        text = resp.text

                        # Emails
                        found = EMAIL_REGEX.findall(text)
                        emails.update(found)

                        # mailto: links
                        soup = BeautifulSoup(text, "html.parser")
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if href.startswith("mailto:"):
                                email = href.replace("mailto:", "").split("?")[0]
                                emails.add(email)
                            # Social links
                            for social in ["linkedin.com", "twitter.com", "x.com", "github.com", "facebook.com"]:
                                if social in href:
                                    socials.add(href)

                        # Phone regex
                        phone_matches = re.findall(r"[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}", text)
                        phones.update(p.strip() for p in phone_matches if len(p.strip()) >= 10)

                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        continue

        except Exception as e:
            logger.warning(f"Email harvester failed: {e}")

        # Filter emails to target domain
        domain_emails = {e for e in emails if domain.split(".")[-2] in e.lower()}
        other_emails = emails - domain_emails

        if domain_emails:
            findings.append(Finding(
                title=f"Harvested {len(domain_emails)} emails from {domain}",
                severity=Severity.LOW,
                cvss_score=3.7,
                description=f"Email addresses found on target website",
                evidence="\n".join(sorted(domain_emails)),
                remediation="Consider obfuscating email addresses on public pages to prevent scraping.",
                category="osint",
                metadata={"emails": list(domain_emails)},
            ))

        if other_emails:
            findings.append(Finding(
                title=f"Third-party emails found ({len(other_emails)})",
                severity=Severity.INFO,
                evidence="\n".join(sorted(other_emails)[:20]),
                category="osint",
            ))

        if phones:
            findings.append(Finding(
                title=f"Phone numbers found ({len(phones)})",
                severity=Severity.INFO,
                evidence="\n".join(sorted(phones)[:10]),
                category="osint",
            ))

        if socials:
            findings.append(Finding(
                title=f"Social media profiles ({len(socials)})",
                severity=Severity.INFO,
                evidence="\n".join(sorted(socials)[:15]),
                category="osint",
            ))

        return findings
