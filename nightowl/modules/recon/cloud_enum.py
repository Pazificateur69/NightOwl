"""Cloud infrastructure enumeration (AWS, GCP, Azure)."""

import asyncio
import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

AWS_CHECKS = [
    ("s3", "https://{}.s3.amazonaws.com", [200, 403]),
    ("s3-website", "http://{}.s3-website-us-east-1.amazonaws.com", [200, 301]),
    ("cloudfront", "https://{}.cloudfront.net", [200, 403]),
    ("elasticbeanstalk", "https://{}.elasticbeanstalk.com", [200]),
    ("ec2", "https://ec2.{}.amazonaws.com", [200, 403]),
]

AZURE_CHECKS = [
    ("blob", "https://{}.blob.core.windows.net", [200, 400]),
    ("webapp", "https://{}.azurewebsites.net", [200]),
    ("vault", "https://{}.vault.azure.net", [200, 401]),
    ("database", "https://{}.database.windows.net", [200]),
]

GCP_CHECKS = [
    ("storage", "https://storage.googleapis.com/{}", [200, 403]),
    ("appspot", "https://{}.appspot.com", [200]),
    ("firebaseio", "https://{}.firebaseio.com/.json", [200]),
    ("cloudfunctions", "https://us-central1-{}.cloudfunctions.net", [200, 404]),
]


class CloudEnumPlugin(ScannerPlugin):
    name = "cloud-enum"
    description = "Enumerate cloud resources (AWS S3, Azure Blob, GCP Storage, Firebase)"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        domain = target.domain or target.host
        base_name = domain.split(".")[0]
        names = [base_name, domain.replace(".", "-"), base_name + "-dev", base_name + "-staging", base_name + "-prod", base_name + "-backup", base_name + "-assets", base_name + "-data"]

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8) as client:
            for name in names:
                # AWS
                for svc, url_tpl, ok_codes in AWS_CHECKS:
                    await self._check(client, findings, "AWS", svc, url_tpl.format(name), ok_codes, name)
                # Azure
                for svc, url_tpl, ok_codes in AZURE_CHECKS:
                    await self._check(client, findings, "Azure", svc, url_tpl.format(name), ok_codes, name)
                # GCP
                for svc, url_tpl, ok_codes in GCP_CHECKS:
                    await self._check(client, findings, "GCP", svc, url_tpl.format(name), ok_codes, name)

                await asyncio.sleep(0.05)

        return findings

    async def _check(self, client, findings, cloud, service, url, ok_codes, name):
        try:
            resp = await client.get(url)
            if resp.status_code in ok_codes:
                sev = Severity.HIGH if resp.status_code == 200 else Severity.MEDIUM
                is_public = resp.status_code == 200
                findings.append(Finding(
                    title=f"{cloud} {service} found: {name}" + (" (PUBLIC)" if is_public else ""),
                    severity=sev,
                    cvss_score=7.5 if is_public else 4.3,
                    description=f"{cloud} {service} resource exists for '{name}'" + (" and is publicly accessible" if is_public else ""),
                    evidence=f"URL: {url}\nStatus: {resp.status_code}\nPublic: {is_public}\nHeaders: {dict(list(resp.headers.items())[:5])}",
                    remediation=f"Review {cloud} {service} bucket/resource permissions. Restrict public access." if is_public else f"Resource exists, verify access controls.",
                    category="cloud-enum",
                    metadata={"cloud": cloud, "service": service, "public": is_public},
                ))
        except Exception:
            pass
