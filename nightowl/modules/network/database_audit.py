"""Audit common database services for unauthenticated access."""

import asyncio
import logging
import httpx
import socket

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Default timeout for socket operations (seconds)
SOCKET_TIMEOUT = 5


def _tcp_connect(host: str, port: int, timeout: float = SOCKET_TIMEOUT) -> socket.socket | None:
    """Attempt a TCP connection. Returns socket on success, None on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except (OSError, RuntimeError, ValueError, Exception) as exc:
        logger.debug(f"Error: {exc}")
        try:
            s.close()
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")
        return None


def _tcp_send_recv(
    host: str,
    port: int,
    data: bytes | None = None,
    recv_size: int = 4096,
    timeout: float = SOCKET_TIMEOUT,
) -> bytes | None:
    """Connect, optionally send data, receive response."""
    s = _tcp_connect(host, port, timeout)
    if s is None:
        return None
    try:
        if data is not None:
            s.sendall(data)
        return s.recv(recv_size)
    except (OSError, RuntimeError, ValueError, Exception) as exc:
        logger.debug(f"Error: {exc}")
        return None
    finally:
        try:
            s.close()
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")


class DatabaseAuditPlugin(ScannerPlugin):
    name = "database-audit"
    description = "Check common databases for unauthenticated or misconfigured access"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        host = target.ip or target.host
        timeout = float(self.config.get("timeout", SOCKET_TIMEOUT))

        checks = [
            self._check_mysql(host, timeout),
            self._check_postgres(host, timeout),
            self._check_mongodb(host, timeout),
            self._check_redis(host, timeout),
            self._check_elasticsearch(host, timeout),
            self._check_couchdb(host, timeout),
            self._check_memcached(host, timeout),
        ]

        results = await asyncio.gather(*checks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Database check raised exception: {result}")
                continue
            if isinstance(result, list):
                findings.extend(result)

        return findings

    # ── MySQL (3306) ──────────────────────────────────────────────

    async def _check_mysql(self, host: str, timeout: float) -> list[Finding]:
        findings: list[Finding] = []
        port = 3306

        banner = await asyncio.to_thread(_tcp_send_recv, host, port, None, 1024, timeout)
        if banner is None:
            return findings

        findings.append(Finding(
            title=f"MySQL service detected on {host}:{port}",
            severity=Severity.INFO,
            evidence=f"Host: {host}:{port}\nBanner (hex): {banner[:80].hex()}\nBanner (ascii): {banner[:80]!r}",
            category="database-audit",
            port=port,
            protocol="tcp",
        ))

        # Check for server greeting — MySQL protocol starts with packet length + sequence + version
        # A valid greeting means the server is accepting connections
        if len(banner) > 5:
            # Try to parse version string from greeting packet
            try:
                # Skip 4-byte packet header + 1-byte protocol version
                version_end = banner.find(b"\x00", 5)
                if version_end > 5:
                    version = banner[5:version_end].decode("ascii", errors="replace")
                    findings.append(Finding(
                        title=f"MySQL version exposed: {version}",
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        evidence=f"Host: {host}:{port}\nVersion: {version}",
                        remediation="Hide MySQL version string. Restrict network access to database ports.",
                        category="database-audit",
                        port=port,
                        metadata={"service": "mysql", "version": version},
                    ))
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")

        # Try anonymous/root login without password
        # MySQL handshake: after greeting we can attempt auth
        # We do a lightweight check: try to complete handshake with empty password
        auth_response = await asyncio.to_thread(
            self._mysql_try_anon, host, port, timeout
        )
        if auth_response:
            findings.append(Finding(
                title=f"MySQL anonymous/root login possible on {host}:{port}",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="MySQL server accepts connections with empty password for root or anonymous user",
                evidence=f"Host: {host}:{port}\nResponse: {auth_response!r}",
                remediation="Set strong passwords for all MySQL accounts. Remove anonymous users. Restrict network access.",
                category="database-audit",
                port=port,
                metadata={"service": "mysql", "vuln": "anonymous_auth"},
            ))

        return findings

    def _mysql_try_anon(self, host: str, port: int, timeout: float) -> str | None:
        """Attempt MySQL anonymous auth using raw socket protocol."""
        s = _tcp_connect(host, port, timeout)
        if s is None:
            return None
        try:
            # Read greeting
            greeting = s.recv(4096)
            if len(greeting) < 5:
                return None

            # Build a minimal auth response for user 'root' with empty password
            # Capabilities: CLIENT_PROTOCOL_41
            user = b"root\x00"
            auth_data = b"\x00"  # empty password (0-length auth response)
            # Simple capability flags: PROTOCOL_41 | SECURE_CONNECTION
            cap = (0x00000200 | 0x00008000).to_bytes(4, "little")
            max_packet = (1 << 24 - 1).to_bytes(4, "little")
            charset = b"\x21"  # utf8
            reserved = b"\x00" * 23
            payload = cap + max_packet + charset + reserved + user + auth_data
            # Packet header: length(3) + sequence(1)
            header = len(payload).to_bytes(3, "little") + b"\x01"
            s.sendall(header + payload)

            resp = s.recv(4096)
            # OK packet starts with 0x00, ERR packet starts with 0xff
            if resp and len(resp) > 4 and resp[4] == 0x00:
                return "AUTH_OK"
            return None
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            return None
        finally:
            try:
                s.close()
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")

    # ── PostgreSQL (5432) ─────────────────────────────────────────

    async def _check_postgres(self, host: str, timeout: float) -> list[Finding]:
        findings: list[Finding] = []
        port = 5432

        s = _tcp_connect(host, port, timeout)
        if s is None:
            return findings

        try:
            # Send SSLRequest to check if the port is PostgreSQL
            # SSLRequest: 8 bytes, first 4 = length, next 4 = code 80877103
            ssl_request = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
            s.sendall(ssl_request)
            resp = s.recv(1)

            if resp in (b"S", b"N"):
                # 'S' = SSL supported, 'N' = SSL not supported — both confirm PostgreSQL
                ssl_str = "SSL supported" if resp == b"S" else "SSL not supported"
                findings.append(Finding(
                    title=f"PostgreSQL detected on {host}:{port}",
                    severity=Severity.INFO,
                    evidence=f"Host: {host}:{port}\nSSL: {ssl_str}",
                    category="database-audit",
                    port=port,
                    protocol="tcp",
                ))

                if resp == b"N":
                    findings.append(Finding(
                        title=f"PostgreSQL without SSL on {host}:{port}",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description="PostgreSQL server does not require SSL for connections",
                        evidence=f"Host: {host}:{port}\nSSL response: N (not supported)",
                        remediation="Enable SSL/TLS for PostgreSQL connections (ssl = on in postgresql.conf).",
                        category="database-audit",
                        port=port,
                        metadata={"service": "postgresql", "ssl": False},
                    ))
        except Exception as e:
            logger.debug(f"PostgreSQL check failed for {host}:{port}: {e}")
        finally:
            try:
                s.close()
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")

        # Try startup with trust auth (no password)
        auth_result = await asyncio.to_thread(
            self._postgres_try_trust, host, port, timeout
        )
        if auth_result:
            findings.append(Finding(
                title=f"PostgreSQL trust authentication on {host}:{port}",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="PostgreSQL accepts connections without password (trust auth)",
                evidence=f"Host: {host}:{port}\nAuth result: {auth_result}",
                remediation="Change pg_hba.conf from 'trust' to 'scram-sha-256' or 'md5'. Set passwords for all accounts.",
                category="database-audit",
                port=port,
                metadata={"service": "postgresql", "vuln": "trust_auth"},
            ))

        return findings

    def _postgres_try_trust(self, host: str, port: int, timeout: float) -> str | None:
        """Try connecting to PostgreSQL with no password."""
        s = _tcp_connect(host, port, timeout)
        if s is None:
            return None
        try:
            # Build startup message: version 3.0, user=postgres, database=postgres
            user = b"user\x00postgres\x00database\x00postgres\x00\x00"
            version = (3 << 16).to_bytes(4, "big")  # 3.0
            length = (4 + len(version) + len(user)).to_bytes(4, "big")
            s.sendall(length + version + user)

            resp = s.recv(4096)
            if not resp:
                return None

            msg_type = chr(resp[0])
            # 'R' = Authentication message
            if msg_type == "R" and len(resp) >= 8:
                auth_type = int.from_bytes(resp[5:9], "big")
                if auth_type == 0:
                    # AuthenticationOk — trust or no password needed
                    return "AuthenticationOk (trust)"
            return None
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            return None
        finally:
            try:
                s.close()
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")

    # ── MongoDB (27017) ──────────────────────────────────────────

    async def _check_mongodb(self, host: str, timeout: float) -> list[Finding]:
        findings: list[Finding] = []
        port = 27017

        # MongoDB wire protocol: send an isMaster command or try HTTP endpoint
        # Many MongoDB instances expose an HTTP status page on 27017
        resp = await asyncio.to_thread(
            _tcp_send_recv, host, port,
            b"GET /serverStatus HTTP/1.0\r\nHost: localhost\r\n\r\n",
            4096, timeout,
        )

        if resp is None:
            # Try raw connect to check if port is open
            s = _tcp_connect(host, port, timeout)
            if s is None:
                return findings
            try:
                # MongoDB sends a banner or expects OP_MSG
                s.settimeout(timeout)
                # Try to read any greeting
                try:
                    data = s.recv(4096)
                    if data:
                        findings.append(Finding(
                            title=f"MongoDB service detected on {host}:{port}",
                            severity=Severity.INFO,
                            evidence=f"Host: {host}:{port}\nRaw banner: {data[:200]!r}",
                            category="database-audit",
                            port=port,
                        ))
                except socket.timeout:
                    # Port open but no banner: still likely MongoDB
                    findings.append(Finding(
                        title=f"Service on {host}:{port} (possible MongoDB)",
                        severity=Severity.INFO,
                        evidence=f"Host: {host}:{port}\nPort open, no greeting banner",
                        category="database-audit",
                        port=port,
                    ))
            finally:
                try:
                    s.close()
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
            return findings

        resp_str = resp.decode("utf-8", errors="replace")

        if "serverStatus" in resp_str or "ismaster" in resp_str.lower() or "mongodb" in resp_str.lower():
            findings.append(Finding(
                title=f"MongoDB unauthenticated access on {host}:{port}",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="MongoDB exposes server status without authentication",
                evidence=f"Host: {host}:{port}\nResponse:\n{resp_str[:1000]}",
                remediation="Enable MongoDB authentication (--auth flag). Bind to localhost or use firewall rules.",
                category="database-audit",
                port=port,
                metadata={"service": "mongodb", "vuln": "no_auth"},
            ))
        elif resp:
            findings.append(Finding(
                title=f"MongoDB service detected on {host}:{port}",
                severity=Severity.INFO,
                evidence=f"Host: {host}:{port}\nResponse (partial): {resp_str[:500]}",
                category="database-audit",
                port=port,
            ))

        return findings

    # ── Redis (6379) ─────────────────────────────────────────────

    async def _check_redis(self, host: str, timeout: float) -> list[Finding]:
        findings: list[Finding] = []
        port = 6379

        resp = await asyncio.to_thread(
            _tcp_send_recv, host, port, b"PING\r\n", 1024, timeout
        )

        if resp is None:
            return findings

        resp_str = resp.decode("utf-8", errors="replace").strip()

        if "+PONG" in resp_str:
            findings.append(Finding(
                title=f"Redis unauthenticated access on {host}:{port}",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="Redis responds to PING without authentication, allowing full read/write access",
                evidence=f"Host: {host}:{port}\nSent: PING\nResponse: {resp_str}",
                remediation=(
                    "Enable Redis authentication (requirepass). "
                    "Bind Redis to localhost (bind 127.0.0.1). "
                    "Use firewall rules to restrict access."
                ),
                category="database-audit",
                port=port,
                metadata={"service": "redis", "vuln": "no_auth"},
            ))

            # Try to get server info
            info_resp = await asyncio.to_thread(
                _tcp_send_recv, host, port, b"INFO server\r\n", 8192, timeout
            )
            if info_resp:
                info_str = info_resp.decode("utf-8", errors="replace")
                if "redis_version" in info_str:
                    findings.append(Finding(
                        title=f"Redis server info exposed on {host}:{port}",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description="Redis server info is readable without authentication",
                        evidence=f"Host: {host}:{port}\n{info_str[:1500]}",
                        remediation="Enable authentication and restrict network access to Redis.",
                        category="database-audit",
                        port=port,
                        metadata={"service": "redis"},
                    ))

        elif "-NOAUTH" in resp_str or "-ERR" in resp_str:
            findings.append(Finding(
                title=f"Redis detected (auth required) on {host}:{port}",
                severity=Severity.INFO,
                evidence=f"Host: {host}:{port}\nResponse: {resp_str}",
                category="database-audit",
                port=port,
            ))

        return findings

    # ── Elasticsearch (9200) ─────────────────────────────────────

    async def _check_elasticsearch(self, host: str, timeout: float) -> list[Finding]:
        findings: list[Finding] = []
        port = 9200

        resp = await asyncio.to_thread(
            _tcp_send_recv, host, port,
            b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            8192, timeout,
        )

        if resp is None:
            return findings

        resp_str = resp.decode("utf-8", errors="replace")

        if "cluster_name" in resp_str or "elasticsearch" in resp_str.lower():
            sev = Severity.CRITICAL if "cluster_name" in resp_str else Severity.HIGH
            findings.append(Finding(
                title=f"Elasticsearch unauthenticated access on {host}:{port}",
                severity=sev,
                cvss_score=9.1 if sev == Severity.CRITICAL else 7.5,
                description="Elasticsearch cluster is accessible without authentication",
                evidence=f"Host: {host}:{port}\nResponse:\n{resp_str[:1500]}",
                remediation=(
                    "Enable Elasticsearch security features (xpack.security.enabled: true). "
                    "Set up authentication. Bind to localhost or use firewall."
                ),
                category="database-audit",
                port=port,
                metadata={"service": "elasticsearch", "vuln": "no_auth"},
            ))

            # Try to list indices
            idx_resp = await asyncio.to_thread(
                _tcp_send_recv, host, port,
                b"GET /_cat/indices HTTP/1.0\r\nHost: localhost\r\n\r\n",
                16384, timeout,
            )
            if idx_resp:
                idx_str = idx_resp.decode("utf-8", errors="replace")
                if "green" in idx_str or "yellow" in idx_str or "red" in idx_str:
                    findings.append(Finding(
                        title=f"Elasticsearch indices exposed on {host}:{port}",
                        severity=Severity.HIGH,
                        cvss_score=8.0,
                        evidence=f"Host: {host}:{port}\nIndices:\n{idx_str[:2000]}",
                        remediation="Restrict Elasticsearch API access. Enable X-Pack security.",
                        category="database-audit",
                        port=port,
                    ))

        return findings

    # ── CouchDB (5984) ───────────────────────────────────────────

    async def _check_couchdb(self, host: str, timeout: float) -> list[Finding]:
        findings: list[Finding] = []
        port = 5984

        resp = await asyncio.to_thread(
            _tcp_send_recv, host, port,
            b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            4096, timeout,
        )

        if resp is None:
            return findings

        resp_str = resp.decode("utf-8", errors="replace")

        if "couchdb" in resp_str.lower() or '"version"' in resp_str:
            findings.append(Finding(
                title=f"CouchDB accessible on {host}:{port}",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description="CouchDB instance is reachable without authentication",
                evidence=f"Host: {host}:{port}\nResponse:\n{resp_str[:1000]}",
                remediation="Enable CouchDB authentication. Bind to localhost. Use firewall rules.",
                category="database-audit",
                port=port,
                metadata={"service": "couchdb", "vuln": "no_auth"},
            ))

            # Try /_all_dbs
            dbs_resp = await asyncio.to_thread(
                _tcp_send_recv, host, port,
                b"GET /_all_dbs HTTP/1.0\r\nHost: localhost\r\n\r\n",
                8192, timeout,
            )
            if dbs_resp:
                dbs_str = dbs_resp.decode("utf-8", errors="replace")
                if "[" in dbs_str:
                    findings.append(Finding(
                        title=f"CouchDB databases listed on {host}:{port}",
                        severity=Severity.CRITICAL,
                        cvss_score=9.1,
                        evidence=f"Host: {host}:{port}\nDatabases:\n{dbs_str[:2000]}",
                        remediation="Enable authentication for CouchDB admin and reader access.",
                        category="database-audit",
                        port=port,
                    ))

        return findings

    # ── Memcached (11211) ────────────────────────────────────────

    async def _check_memcached(self, host: str, timeout: float) -> list[Finding]:
        findings: list[Finding] = []
        port = 11211

        resp = await asyncio.to_thread(
            _tcp_send_recv, host, port, b"stats\r\n", 8192, timeout
        )

        if resp is None:
            return findings

        resp_str = resp.decode("utf-8", errors="replace")

        if "STAT" in resp_str:
            findings.append(Finding(
                title=f"Memcached unauthenticated access on {host}:{port}",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description="Memcached responds to 'stats' command without authentication",
                evidence=f"Host: {host}:{port}\nSent: stats\nResponse:\n{resp_str[:1500]}",
                remediation=(
                    "Enable Memcached SASL authentication. "
                    "Bind to localhost (-l 127.0.0.1). "
                    "Use firewall rules. Disable UDP if not needed (-U 0)."
                ),
                category="database-audit",
                port=port,
                metadata={"service": "memcached", "vuln": "no_auth"},
            ))
        elif "ERROR" in resp_str or "CLIENT_ERROR" in resp_str:
            findings.append(Finding(
                title=f"Memcached detected (restricted) on {host}:{port}",
                severity=Severity.INFO,
                evidence=f"Host: {host}:{port}\nResponse: {resp_str[:500]}",
                category="database-audit",
                port=port,
            ))

        return findings
