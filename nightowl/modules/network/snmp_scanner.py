"""SNMP community string scanner plugin."""

import logging
import socket

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

COMMUNITY_STRINGS = ["public", "private", "community", "manager", "admin", "snmp", "default", "test"]

# SNMPv1 GET request for sysDescr (1.3.6.1.2.1.1.1.0)
SNMP_GET_REQUEST = bytes([
    0x30, 0x26, 0x02, 0x01, 0x00, 0x04,  # SEQUENCE, version, community placeholder
])


class SNMPScannerPlugin(ScannerPlugin):
    name = "snmp-scanner"
    description = "Test for default SNMP community strings"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        host = target.ip or target.host

        for community in COMMUNITY_STRINGS:
            try:
                # Build SNMPv1 GET sysDescr.0
                comm_bytes = community.encode()
                pdu = self._build_snmp_get(comm_bytes)

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(pdu, (host, 161))

                try:
                    data, _ = sock.recvfrom(4096)
                    if data and len(data) > 10:
                        findings.append(Finding(
                            title=f"SNMP community string found: '{community}'",
                            severity=Severity.HIGH if community in ("public", "private") else Severity.CRITICAL,
                            cvss_score=7.5,
                            description=f"SNMP responds to community string '{community}'",
                            evidence=f"Host: {host}:161\nCommunity: {community}\nResponse size: {len(data)} bytes",
                            remediation="Change default SNMP community strings. Use SNMPv3 with authentication.",
                            category="snmp",
                        ))
                except socket.timeout:
                    pass
                finally:
                    sock.close()

            except Exception as e:
                logger.debug(f"SNMP test failed for {community}@{host}: {e}")

        return findings

    def _build_snmp_get(self, community: bytes) -> bytes:
        """Build a minimal SNMPv1 GET request for sysDescr."""
        # OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        varbind = bytes([0x30, len(oid) + 2]) + oid + bytes([0x05, 0x00])
        varbind_list = bytes([0x30, len(varbind)]) + varbind
        request_id = bytes([0x02, 0x01, 0x01])
        error = bytes([0x02, 0x01, 0x00])
        error_idx = bytes([0x02, 0x01, 0x00])
        pdu_content = request_id + error + error_idx + varbind_list
        pdu = bytes([0xa0, len(pdu_content)]) + pdu_content
        version = bytes([0x02, 0x01, 0x00])
        comm = bytes([0x04, len(community)]) + community
        message = version + comm + pdu
        return bytes([0x30, len(message)]) + message
