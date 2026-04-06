"""Map findings to compliance frameworks (PCI-DSS, OWASP, NIST, ISO 27001)."""

import logging

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Mapping: finding category/keyword -> compliance requirements
COMPLIANCE_MAP = {
    "sql injection": {
        "owasp": "A03:2021 - Injection",
        "pci_dss": "6.5.1 - Injection Flaws",
        "nist": "SI-10 - Information Input Validation",
        "iso27001": "A.14.2.5 - Secure System Engineering",
        "cwe": "CWE-89",
    },
    "xss": {
        "owasp": "A03:2021 - Injection",
        "pci_dss": "6.5.7 - Cross-Site Scripting",
        "nist": "SI-10 - Information Input Validation",
        "iso27001": "A.14.2.5 - Secure System Engineering",
        "cwe": "CWE-79",
    },
    "csrf": {
        "owasp": "A01:2021 - Broken Access Control",
        "pci_dss": "6.5.9 - Cross-Site Request Forgery",
        "nist": "SC-23 - Session Authenticity",
        "iso27001": "A.14.2.5 - Secure System Engineering",
        "cwe": "CWE-352",
    },
    "ssrf": {
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "pci_dss": "6.5.10 - Broken Access Control",
        "nist": "SC-7 - Boundary Protection",
        "iso27001": "A.13.1.1 - Network Controls",
        "cwe": "CWE-918",
    },
    "authentication": {
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "pci_dss": "8.1 - User Identification Management",
        "nist": "IA-2 - Identification and Authentication",
        "iso27001": "A.9.2.1 - User Registration and De-registration",
        "cwe": "CWE-287",
    },
    "crypto": {
        "owasp": "A02:2021 - Cryptographic Failures",
        "pci_dss": "4.1 - Strong Cryptography for Transmission",
        "nist": "SC-13 - Cryptographic Protection",
        "iso27001": "A.10.1.1 - Policy on Use of Cryptographic Controls",
        "cwe": "CWE-327",
    },
    "ssl": {
        "owasp": "A02:2021 - Cryptographic Failures",
        "pci_dss": "2.3 - Encrypt Non-Console Admin Access",
        "nist": "SC-8 - Transmission Confidentiality",
        "iso27001": "A.10.1.1 - Cryptographic Controls",
        "cwe": "CWE-295",
    },
    "misconfiguration": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "pci_dss": "2.2 - Configuration Standards",
        "nist": "CM-6 - Configuration Settings",
        "iso27001": "A.14.2.5 - Secure System Engineering",
        "cwe": "CWE-16",
    },
    "access control": {
        "owasp": "A01:2021 - Broken Access Control",
        "pci_dss": "7.1 - Limit Access to System Components",
        "nist": "AC-3 - Access Enforcement",
        "iso27001": "A.9.4.1 - Information Access Restriction",
        "cwe": "CWE-284",
    },
    "deserialization": {
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "pci_dss": "6.5.8 - Improper Error Handling",
        "nist": "SI-10 - Information Input Validation",
        "iso27001": "A.14.2.5 - Secure System Engineering",
        "cwe": "CWE-502",
    },
    "xxe": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "pci_dss": "6.5.1 - Injection Flaws",
        "nist": "SI-10 - Information Input Validation",
        "iso27001": "A.14.2.5 - Secure System Engineering",
        "cwe": "CWE-611",
    },
    "ssti": {
        "owasp": "A03:2021 - Injection",
        "pci_dss": "6.5.1 - Injection Flaws",
        "nist": "SI-10 - Information Input Validation",
        "iso27001": "A.14.2.5 - Secure System Engineering",
        "cwe": "CWE-1336",
    },
    "path traversal": {
        "owasp": "A01:2021 - Broken Access Control",
        "pci_dss": "6.5.8 - Improper Access Control",
        "nist": "AC-3 - Access Enforcement",
        "iso27001": "A.9.4.1 - Information Access Restriction",
        "cwe": "CWE-22",
    },
    "cors": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "pci_dss": "6.5.10 - Broken Access Control",
        "nist": "AC-4 - Information Flow Enforcement",
        "iso27001": "A.13.1.1 - Network Controls",
        "cwe": "CWE-942",
    },
    "jwt": {
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "pci_dss": "8.2 - Authentication Mechanisms",
        "nist": "IA-5 - Authenticator Management",
        "iso27001": "A.9.4.2 - Secure Log-on Procedures",
        "cwe": "CWE-347",
    },
    "open redirect": {
        "owasp": "A01:2021 - Broken Access Control",
        "pci_dss": "6.5.10 - Broken Access Control",
        "nist": "SI-10 - Information Input Validation",
        "iso27001": "A.14.2.5 - Secure System Engineering",
        "cwe": "CWE-601",
    },
    "default credentials": {
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "pci_dss": "2.1 - Change Vendor Defaults",
        "nist": "IA-5 - Authenticator Management",
        "iso27001": "A.9.3.1 - Use of Secret Authentication Info",
        "cwe": "CWE-798",
    },
    "header": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "pci_dss": "6.5.10 - Broken Access Control",
        "nist": "SC-8 - Transmission Confidentiality",
        "iso27001": "A.14.1.2 - Securing Application Services",
        "cwe": "CWE-693",
    },
}

KEYWORDS_TO_CATEGORY = {
    "sqli": "sql injection", "sql inject": "sql injection", "sql": "sql injection",
    "xss": "xss", "cross-site scripting": "xss", "reflected": "xss",
    "csrf": "csrf", "cross-site request": "csrf",
    "ssrf": "ssrf", "server-side request": "ssrf",
    "auth": "authentication", "login": "authentication", "credential": "default credentials",
    "default cred": "default credentials", "password": "authentication",
    "ssl": "ssl", "tls": "ssl", "certificate": "ssl",
    "header": "header", "hsts": "header", "csp": "header",
    "cors": "cors", "access-control": "cors",
    "deserialization": "deserialization", "deserializ": "deserialization",
    "xxe": "xxe", "xml external": "xxe",
    "ssti": "ssti", "template inject": "ssti",
    "traversal": "path traversal", "lfi": "path traversal", "rfi": "path traversal",
    "jwt": "jwt", "token": "jwt",
    "redirect": "open redirect",
    "config": "misconfiguration", "misconfig": "misconfiguration",
    "idor": "access control", "access": "access control",
}


class ComplianceMapperPlugin(ScannerPlugin):
    name = "compliance-mapper"
    description = "Map findings to PCI-DSS, OWASP, NIST, ISO 27001 compliance frameworks"
    version = "1.0.0"
    stage = "post"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        existing_findings = kwargs.get("findings", [])

        if not existing_findings:
            logger.info(f"[{self.name}] No findings to map")
            return findings

        compliance_summary = {
            "owasp": {}, "pci_dss": {}, "nist": {}, "iso27001": {}
        }

        for f in existing_findings:
            category = self._categorize(f)
            if not category or category not in COMPLIANCE_MAP:
                continue

            mapping = COMPLIANCE_MAP[category]
            for framework, requirement in mapping.items():
                if framework == "cwe":
                    continue
                if requirement not in compliance_summary[framework]:
                    compliance_summary[framework][requirement] = []
                compliance_summary[framework][requirement].append(f.get("title", "") if isinstance(f, dict) else f.title)

        for framework, requirements in compliance_summary.items():
            if not requirements:
                continue

            evidence_lines = []
            for req, finding_titles in requirements.items():
                evidence_lines.append(f"  {req}")
                for title in finding_titles[:3]:
                    evidence_lines.append(f"    - {title}")

            findings.append(Finding(
                title=f"Compliance: {len(requirements)} {framework.upper()} requirements affected",
                description=f"{len(requirements)} {framework.upper()} requirements are impacted by scan findings",
                severity=Severity.INFO,
                category="compliance",
                evidence="\n".join(evidence_lines),
                remediation=f"Address the underlying vulnerabilities to meet {framework.upper()} compliance",
                metadata={
                    "framework": framework,
                    "requirements": list(requirements.keys()),
                    "affected_count": len(requirements),
                },
            ))

        logger.info(f"[{self.name}] Mapped to {len(findings)} compliance frameworks")
        return findings

    def _categorize(self, finding) -> str | None:
        title = (finding.get("title", "") if isinstance(finding, dict) else finding.title).lower()
        desc = (finding.get("description", "") if isinstance(finding, dict) else finding.description).lower()
        text = f"{title} {desc}"

        for keyword, category in KEYWORDS_TO_CATEGORY.items():
            if keyword in text:
                return category
        return None
