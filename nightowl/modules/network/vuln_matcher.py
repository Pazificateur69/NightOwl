"""Vulnerability matcher that correlates service versions against known CVEs."""

import logging
import re

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Local lookup of common CVEs by product/version pattern.
# Keys are (product_regex, version_constraint) tuples.
# This is intentionally a curated subset for offline matching.
KNOWN_VULNS: list[dict] = [
    # Apache HTTP Server
    {
        "product_pattern": r"(?i)apache\s*httpd?",
        "version_range": ("2.4.0", "2.4.49"),
        "cve": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal",
        "description": "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49.",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        "remediation": "Upgrade Apache HTTP Server to version 2.4.50 or later.",
    },
    {
        "product_pattern": r"(?i)apache\s*httpd?",
        "version_range": ("2.4.0", "2.4.50"),
        "cve": "CVE-2021-42013",
        "title": "Apache HTTP Server Path Traversal (Bypass)",
        "description": "Path traversal attack bypass in Apache HTTP Server 2.4.50.",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
    },
    # OpenSSH
    {
        "product_pattern": r"(?i)openssh",
        "version_range": ("8.5", "9.7"),
        "cve": "CVE-2024-6387",
        "title": "OpenSSH regreSSHion RCE",
        "description": "Signal handler race condition in OpenSSH server (sshd) allows unauthenticated remote code execution.",
        "severity": Severity.CRITICAL,
        "cvss": 8.1,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
        "remediation": "Upgrade OpenSSH to version 9.8 or later.",
    },
    {
        "product_pattern": r"(?i)openssh",
        "version_range": ("0.0", "7.6"),
        "cve": "CVE-2018-15473",
        "title": "OpenSSH User Enumeration",
        "description": "OpenSSH through 7.7 allows user enumeration via malformed authentication requests.",
        "severity": Severity.MEDIUM,
        "cvss": 5.3,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
        "remediation": "Upgrade OpenSSH to version 7.8 or later.",
    },
    # ProFTPD
    {
        "product_pattern": r"(?i)proftpd",
        "version_range": ("1.3.0", "1.3.5"),
        "cve": "CVE-2015-3306",
        "title": "ProFTPD mod_copy Remote Code Execution",
        "description": "The mod_copy module in ProFTPD allows remote attackers to read and write arbitrary files.",
        "severity": Severity.CRITICAL,
        "cvss": 10.0,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
        "remediation": "Upgrade ProFTPD to 1.3.5b or later, or disable mod_copy.",
    },
    # vsftpd
    {
        "product_pattern": r"(?i)vsftpd",
        "version_range": ("2.3.4", "2.3.4"),
        "cve": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Backdoor",
        "description": "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200.",
        "severity": Severity.CRITICAL,
        "cvss": 10.0,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
        "remediation": "Upgrade to a non-compromised version of vsftpd.",
    },
    # Samba / SMB
    {
        "product_pattern": r"(?i)samba",
        "version_range": ("3.5.0", "4.6.4"),
        "cve": "CVE-2017-7494",
        "title": "Samba Remote Code Execution (SambaCry)",
        "description": "Samba allows remote code execution via a writable share (similar to WannaCry).",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7494"],
        "remediation": "Upgrade Samba to 4.6.5, 4.5.11, or 4.4.14 or later.",
    },
    # nginx
    {
        "product_pattern": r"(?i)nginx",
        "version_range": ("0.6.18", "1.13.2"),
        "cve": "CVE-2017-7529",
        "title": "nginx Integer Overflow Information Disclosure",
        "description": "Integer overflow in nginx range filter allows disclosure of potentially sensitive information.",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7529"],
        "remediation": "Upgrade nginx to 1.13.3 or 1.12.1 or later.",
    },
    # MySQL
    {
        "product_pattern": r"(?i)mysql",
        "version_range": ("5.5.0", "5.5.52"),
        "cve": "CVE-2016-6662",
        "title": "MySQL Remote Root Code Execution",
        "description": "MySQL allows authenticated users to achieve remote root code execution via config file injection.",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-6662"],
        "remediation": "Upgrade MySQL to the latest patched version.",
    },
    # Redis
    {
        "product_pattern": r"(?i)redis",
        "version_range": ("2.0.0", "7.0.11"),
        "cve": "CVE-2023-28856",
        "title": "Redis HINCRBYFLOAT Denial of Service",
        "description": "Authenticated users can use the HINCRBYFLOAT command to crash the Redis server.",
        "severity": Severity.MEDIUM,
        "cvss": 6.5,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-28856"],
        "remediation": "Upgrade Redis to 7.0.12, 6.2.13, or later.",
    },
    # Microsoft SMB (EternalBlue)
    {
        "product_pattern": r"(?i)microsoft.*(smb|windows)",
        "version_range": ("0.0", "99.99"),
        "cve": "CVE-2017-0144",
        "title": "EternalBlue SMB Remote Code Execution",
        "description": (
            "The SMBv1 server in Microsoft Windows allows remote code execution "
            "via crafted packets (MS17-010/EternalBlue). Version-specific check required."
        ),
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
        "remediation": "Apply MS17-010 patch and disable SMBv1.",
    },
    # PostgreSQL
    {
        "product_pattern": r"(?i)postgres",
        "version_range": ("9.3.0", "14.3"),
        "cve": "CVE-2022-2625",
        "title": "PostgreSQL Extension Script Replacement",
        "description": "A malicious extension script can replace objects from other extensions during CREATE OR REPLACE.",
        "severity": Severity.HIGH,
        "cvss": 8.0,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-2625"],
        "remediation": "Upgrade PostgreSQL to the latest patched version.",
    },
]


def _parse_version(ver_str: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of integers."""
    parts = re.findall(r"\d+", ver_str)
    if not parts:
        return (0,)
    return tuple(int(p) for p in parts[:4])


def _version_in_range(version: str, ver_min: str, ver_max: str) -> bool:
    """Check whether a version falls within an inclusive range."""
    try:
        v = _parse_version(version)
        lo = _parse_version(ver_min)
        hi = _parse_version(ver_max)
        return lo <= v <= hi
    except Exception:
        return False


class VulnMatcherPlugin(ScannerPlugin):
    """Matches discovered services/versions against known CVE database."""

    name = "vuln-matcher"
    description = "Matches service versions against known CVEs from a local vulnerability database"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        scan_findings: list[Finding] = kwargs.get("findings", [])

        if not scan_findings:
            logger.warning("[vuln-matcher] No scan findings provided to match against")
            return findings

        for scan_finding in scan_findings:
            meta = scan_finding.metadata
            product = meta.get("product", "")
            version = meta.get("version", "")
            cpe = meta.get("cpe", "")

            if not product:
                continue

            search_str = product
            if cpe:
                search_str += f" {cpe}"

            for vuln in KNOWN_VULNS:
                pattern = vuln["product_pattern"]
                if not re.search(pattern, search_str, re.IGNORECASE):
                    continue

                ver_min, ver_max = vuln["version_range"]

                if version and not _version_in_range(version, ver_min, ver_max):
                    continue

                port = meta.get("port")
                proto = meta.get("protocol", "tcp")

                findings.append(
                    Finding(
                        title=f'{vuln["cve"]} - {vuln["title"]}',
                        description=(
                            f'{vuln["description"]}\n\n'
                            f"Matched service: {product} {version}\n"
                            f"Affected range: {ver_min} - {ver_max}"
                        ),
                        severity=vuln["severity"],
                        cvss_score=vuln["cvss"],
                        category="vulnerability",
                        port=port,
                        protocol=proto,
                        references=vuln["references"],
                        remediation=vuln["remediation"],
                        evidence=f"Service: {product} {version} (CPE: {cpe})",
                        metadata={
                            "cve": vuln["cve"],
                            "matched_product": product,
                            "matched_version": version,
                            "cpe": cpe,
                            "version_range": vuln["version_range"],
                        },
                    )
                )

        logger.info(
            f"[vuln-matcher] Matched {len(findings)} CVEs from {len(scan_findings)} service findings"
        )
        return findings
