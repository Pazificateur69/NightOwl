"""FTP anonymous access scanner plugin."""

import ftplib
import logging
import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class FTPScannerPlugin(ScannerPlugin):
    name = "ftp-scanner"
    description = "Test for anonymous FTP access"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.ip or target.host
        port = target.port or 21

        try:
            ftp = ftplib.FTP(timeout=10)
            ftp.connect(host, port)
            banner = ftp.getwelcome()

            findings.append(Finding(
                title=f"FTP banner: {banner[:100]}",
                severity=Severity.INFO,
                evidence=f"Host: {host}:{port}\nBanner: {banner}",
                category="ftp",
            ))

            # Test anonymous login
            try:
                ftp.login("anonymous", "nightowl@test.com")
                findings.append(Finding(
                    title=f"FTP anonymous access allowed on {host}",
                    severity=Severity.HIGH, cvss_score=7.5,
                    description="FTP server allows anonymous login",
                    evidence=f"Host: {host}:{port}\nLogin: anonymous",
                    remediation="Disable anonymous FTP access unless explicitly required.",
                    category="ftp",
                ))

                # Try to list files
                try:
                    file_list = []
                    ftp.retrlines("LIST", file_list.append)
                    if file_list:
                        listing = "\n".join(file_list[:20])
                        findings.append(Finding(
                            title=f"FTP directory listing ({len(file_list)} items)",
                            severity=Severity.MEDIUM,
                            evidence=f"Directory listing:\n{listing}",
                            category="ftp",
                        ))
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")

            except ftplib.error_perm:
                findings.append(Finding(
                    title="FTP anonymous access denied",
                    severity=Severity.INFO,
                    evidence=f"Host: {host}:{port}\nAnonymous login rejected",
                    category="ftp",
                ))

            ftp.quit()

        except Exception as e:
            logger.debug(f"FTP scan failed for {host}:{port}: {e}")

        return findings
