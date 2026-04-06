"""Cloud IAM and metadata endpoint audit plugin."""

import asyncio
import logging
import re
from urllib.parse import urljoin

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# ── Cloud metadata endpoints ────────────────────────────────────
METADATA_CHECKS = [
    # AWS IMDSv1
    {
        "cloud": "AWS",
        "name": "AWS IMDSv1 metadata",
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {},
        "signatures": ["ami-id", "instance-id", "hostname", "local-ipv4"],
    },
    {
        "cloud": "AWS",
        "name": "AWS IAM security credentials",
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "headers": {},
        "signatures": [],  # any 200 response is a finding
    },
    {
        "cloud": "AWS",
        "name": "AWS user-data",
        "url": "http://169.254.169.254/latest/user-data",
        "headers": {},
        "signatures": [],
    },
    {
        "cloud": "AWS",
        "name": "AWS identity document",
        "url": "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "headers": {},
        "signatures": ["accountId", "instanceId", "region"],
    },
    # GCP
    {
        "cloud": "GCP",
        "name": "GCP metadata",
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "signatures": [],
    },
    {
        "cloud": "GCP",
        "name": "GCP service account token",
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "headers": {"Metadata-Flavor": "Google"},
        "signatures": ["access_token"],
    },
    {
        "cloud": "GCP",
        "name": "GCP project metadata",
        "url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "headers": {"Metadata-Flavor": "Google"},
        "signatures": [],
    },
    # Azure
    {
        "cloud": "Azure",
        "name": "Azure instance metadata",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "signatures": ["vmId", "subscriptionId", "resourceGroupName"],
    },
    {
        "cloud": "Azure",
        "name": "Azure managed identity token",
        "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "headers": {"Metadata": "true"},
        "signatures": ["access_token"],
    },
    # DigitalOcean
    {
        "cloud": "DigitalOcean",
        "name": "DigitalOcean metadata",
        "url": "http://169.254.169.254/metadata/v1/",
        "headers": {},
        "signatures": ["droplet_id", "hostname"],
    },
    {
        "cloud": "DigitalOcean",
        "name": "DigitalOcean metadata JSON",
        "url": "http://169.254.169.254/metadata/v1.json",
        "headers": {},
        "signatures": ["droplet_id"],
    },
]

# Paths on the target that might expose credentials
CREDENTIAL_PATHS = [
    "/.env",
    "/env",
    "/.env.production",
    "/.env.local",
    "/.env.backup",
    "/config/aws",
    "/.aws/credentials",
    "/.aws/config",
    "/config/credentials",
    "/app/.env",
    "/api/.env",
    "/server/.env",
    "/web.config",
    "/wp-config.php.bak",
    "/config.php.bak",
]

# Patterns that indicate AWS credentials in file content
AWS_KEY_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ID
    re.compile(r"aws_access_key_id\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"aws_secret_access_key\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"AWS_ACCESS_KEY_ID\s*=\s*\S+"),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*=\s*\S+"),
    re.compile(r"AZURE_CLIENT_SECRET\s*=\s*\S+"),
    re.compile(r"GOOGLE_APPLICATION_CREDENTIALS\s*=\s*\S+"),
]

# S3 URL patterns to detect in page source
S3_URL_PATTERN = re.compile(
    r"https?://([a-zA-Z0-9._-]+)\.s3[.\-](?:[a-zA-Z0-9-]+\.)?amazonaws\.com"
)


class CloudIAMAuditPlugin(ScannerPlugin):
    name = "cloud-iam-audit"
    description = "Audit cloud metadata endpoints and exposed credentials"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        base_url = target.url or f"https://{target.host}"

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=3,
        ) as client:
            # Phase 1: Check cloud metadata endpoints (SSRF-style via target)
            metadata_findings = await self._check_metadata_endpoints(client, base_url)
            findings.extend(metadata_findings)

            # Phase 2: Check for exposed credential files
            cred_findings = await self._check_credential_files(client, base_url)
            findings.extend(cred_findings)

            # Phase 3: Check for S3 bucket references in page source
            s3_findings = await self._check_s3_in_source(client, base_url)
            findings.extend(s3_findings)

        return findings

    async def _check_metadata_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> list[Finding]:
        """Test cloud metadata endpoints for SSRF or direct access."""
        findings: list[Finding] = []

        for check in METADATA_CHECKS:
            try:
                resp = await client.get(
                    check["url"],
                    headers=check["headers"],
                )

                if resp.status_code != 200:
                    continue

                body = resp.text[:2000]

                # If there are specific signatures, check for them
                if check["signatures"]:
                    matched = [s for s in check["signatures"] if s in body]
                    if not matched:
                        continue
                elif not body.strip():
                    continue

                # Determine severity — credential/token endpoints are CRITICAL
                is_cred = any(kw in check["name"].lower() for kw in ("credential", "token", "identity"))
                sev = Severity.CRITICAL if is_cred else Severity.HIGH
                score = 9.8 if is_cred else 8.0

                findings.append(Finding(
                    title=f"{check['cloud']} metadata exposed: {check['name']}",
                    severity=sev,
                    cvss_score=score,
                    description=(
                        f"Cloud metadata endpoint for {check['cloud']} is accessible. "
                        f"This may leak instance credentials, IAM roles, or infrastructure details."
                    ),
                    evidence=(
                        f"URL: {check['url']}\n"
                        f"Cloud: {check['cloud']}\n"
                        f"Headers sent: {check['headers']}\n"
                        f"Status: {resp.status_code}\n"
                        f"Response:\n{body}"
                    ),
                    remediation=(
                        f"For AWS: Enforce IMDSv2 (HttpTokens=required). "
                        f"For GCP: Restrict metadata access with firewall rules. "
                        f"For Azure: Use managed identity with minimum permissions. "
                        f"Block metadata IPs (169.254.169.254) from application layer."
                    ),
                    category="cloud-iam",
                    metadata={
                        "cloud": check["cloud"],
                        "endpoint": check["url"],
                        "vuln": "metadata_exposure",
                    },
                ))

            except (httpx.ConnectError, httpx.ConnectTimeout):
                # Expected for most targets — metadata IP not routable
                continue
            except Exception as e:
                logger.debug(f"Metadata check failed for {check['name']}: {e}")
                continue

        return findings

    async def _check_credential_files(
        self,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> list[Finding]:
        """Check for exposed credential/env files on the target."""
        findings: list[Finding] = []

        for path in CREDENTIAL_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)

                if resp.status_code != 200:
                    continue

                body = resp.text
                if len(body) < 5:
                    continue

                # Check if content looks like actual credentials (not an error page)
                credential_matches: list[str] = []
                for pattern in AWS_KEY_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        # Redact most of the key for safety
                        raw = match.group(0)
                        if "=" in raw:
                            key, val = raw.split("=", 1)
                            val = val.strip().strip("'\"")
                            redacted = val[:6] + "..." + val[-4:] if len(val) > 10 else val[:4] + "..."
                            credential_matches.append(f"{key.strip()} = {redacted}")
                        else:
                            credential_matches.append(raw[:8] + "..." + raw[-4:])

                # Also detect generic env file patterns
                env_like = any(
                    line.strip() and "=" in line and not line.strip().startswith(("<", "{", "#"))
                    for line in body.splitlines()[:20]
                )

                if credential_matches:
                    findings.append(Finding(
                        title=f"Cloud credentials exposed at {path}",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        description=f"Credential file at {url} contains cloud provider credentials",
                        evidence=(
                            f"URL: {url}\n"
                            f"Credentials found (redacted):\n"
                            + "\n".join(f"  - {m}" for m in credential_matches)
                        ),
                        remediation=(
                            "Remove credential files from web-accessible paths immediately. "
                            "Rotate all exposed credentials. Use environment variables or secret managers."
                        ),
                        category="cloud-iam",
                        metadata={"path": path, "vuln": "exposed_credentials"},
                    ))
                elif env_like:
                    findings.append(Finding(
                        title=f"Environment file exposed at {path}",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description=f"Environment configuration file accessible at {url}",
                        evidence=f"URL: {url}\nContent preview:\n{body[:500]}",
                        remediation="Block access to .env files. Add deny rules in web server configuration.",
                        category="cloud-iam",
                        metadata={"path": path, "vuln": "exposed_env"},
                    ))

            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

            await asyncio.sleep(0.05)

        return findings

    async def _check_s3_in_source(
        self,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> list[Finding]:
        """Check page source for S3 bucket references and test their ACLs."""
        findings: list[Finding] = []

        try:
            resp = await client.get(base_url, follow_redirects=True)
            if resp.status_code != 200:
                return findings

            # Find S3 bucket names in page source
            buckets = set(S3_URL_PATTERN.findall(resp.text))

            for bucket in buckets:
                # Check if bucket allows public listing
                try:
                    bucket_url = f"https://{bucket}.s3.amazonaws.com"
                    bucket_resp = await client.get(bucket_url)

                    if bucket_resp.status_code == 200 and "<ListBucketResult" in bucket_resp.text:
                        findings.append(Finding(
                            title=f"Public S3 bucket listing: {bucket}",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=f"S3 bucket '{bucket}' allows public listing of contents",
                            evidence=(
                                f"Bucket: {bucket}\n"
                                f"URL: {bucket_url}\n"
                                f"Status: {bucket_resp.status_code}\n"
                                f"Response preview:\n{bucket_resp.text[:800]}"
                            ),
                            remediation=(
                                "Enable S3 Block Public Access. Review bucket policy and ACLs. "
                                "Use CloudFront with OAI for public content distribution."
                            ),
                            category="cloud-iam",
                            metadata={"bucket": bucket, "vuln": "public_s3_listing"},
                        ))
                    elif bucket_resp.status_code == 403:
                        findings.append(Finding(
                            title=f"S3 bucket referenced: {bucket} (access denied)",
                            severity=Severity.INFO,
                            evidence=f"Bucket: {bucket}\nFound in page source of: {base_url}",
                            category="cloud-iam",
                        ))

                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

        except Exception as e:
            logger.debug(f"S3 source check failed: {e}")

        return findings
