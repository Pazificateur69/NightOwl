"""GraphQL introspection and security analysis plugin.

Discovers GraphQL endpoints, performs introspection queries, and identifies
security issues such as exposed sensitive types, unrestricted mutations,
and information disclosure via the schema.
"""

import json
import logging
from urllib.parse import urlparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql",
    "/gql",
    "/api/graphql",
    "/api/gql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql/v1",
    "/query",
    "/api/query",
    "/graphiql",
    "/playground",
    "/explorer",
    "/api",
    "/graphql/console",
]

# Full introspection query
INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          description
          fields(includeDeprecated: true) {
            name
            description
            type {
              name
              kind
              ofType {
                name
                kind
              }
            }
            args {
              name
              type { name kind }
            }
          }
        }
        directives {
          name
          description
        }
      }
    }
    """
}

# Simple introspection probe (less likely to be blocked)
SIMPLE_INTROSPECTION = {"query": "{__schema{types{name,fields{name,type{name}}}}}"}

# Type and field names that suggest sensitive data
SENSITIVE_TYPE_NAMES = {
    "user",
    "admin",
    "administrator",
    "password",
    "credential",
    "token",
    "secret",
    "apikey",
    "api_key",
    "payment",
    "creditcard",
    "credit_card",
    "ssn",
    "session",
    "auth",
    "authentication",
    "internal",
    "debug",
    "config",
    "configuration",
    "private",
    "role",
    "permission",
}

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwordhash",
    "password_hash",
    "secret",
    "token",
    "accesstoken",
    "access_token",
    "refreshtoken",
    "refresh_token",
    "apikey",
    "api_key",
    "ssn",
    "creditcard",
    "credit_card_number",
    "cvv",
    "pin",
    "private_key",
    "privatekey",
    "salt",
    "hash",
    "otp",
    "mfa_secret",
    "recovery_code",
    "session_id",
    "internal_id",
    "db_password",
}

# Dangerous mutation patterns
DANGEROUS_MUTATIONS = {
    "delete",
    "remove",
    "drop",
    "reset",
    "admin",
    "createuser",
    "create_user",
    "updatepassword",
    "update_password",
    "changepassword",
    "change_password",
    "setrole",
    "set_role",
    "assignrole",
    "assign_role",
    "elevate",
    "promote",
    "grant",
    "revoke",
    "execute",
    "run",
    "import",
    "export",
}


class GraphQLIntrospectPlugin(ScannerPlugin):
    name = "graphql-introspect"
    description = "Discover GraphQL endpoints and analyze schemas for security issues"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=15
            ) as client:
                # ── Phase 1: Discover GraphQL endpoints ──
                endpoints = await self._discover_endpoints(client, base_url)

                if not endpoints:
                    logger.info(f"No GraphQL endpoints found on {base_url}")
                    return findings

                for endpoint_url in endpoints:
                    # ── Phase 2: Attempt introspection ──
                    schema = await self._introspect(client, endpoint_url)
                    if schema is None:
                        continue

                    # Introspection itself is a finding
                    type_count, field_count, mutation_count = self._count_schema(schema)
                    findings.append(
                        Finding(
                            title=f"GraphQL Introspection Enabled: {endpoint_url}",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            description=(
                                "GraphQL introspection is enabled, exposing the entire API schema. "
                                f"Discovered {type_count} types, {field_count} fields, "
                                f"and {mutation_count} mutations."
                            ),
                            evidence=(
                                f"Endpoint: {endpoint_url}\n"
                                f"Types: {type_count}\n"
                                f"Fields: {field_count}\n"
                                f"Mutations: {mutation_count}"
                            ),
                            remediation=(
                                "Disable introspection in production environments. "
                                "Use schema allowlisting and query depth/complexity limits."
                            ),
                            category="graphql",
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                            ],
                            metadata={"endpoint": endpoint_url},
                        )
                    )

                    # ── Phase 3: Analyze schema for sensitive types ──
                    sensitive_findings = self._analyze_sensitive_types(
                        schema, endpoint_url
                    )
                    findings.extend(sensitive_findings)

                    # ── Phase 4: Analyze mutations ──
                    mutation_findings = self._analyze_mutations(schema, endpoint_url)
                    findings.extend(mutation_findings)

                    # ── Phase 5: Test unauthenticated mutation access ──
                    unauth_findings = await self._test_unauth_mutations(
                        client, endpoint_url, schema
                    )
                    findings.extend(unauth_findings)

        except Exception as e:
            logger.warning(f"GraphQL introspection scan failed: {e}")

        return findings

    async def _discover_endpoints(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[str]:
        """Probe common GraphQL endpoint paths."""
        found: list[str] = []
        for path in GRAPHQL_PATHS:
            endpoint = f"{base_url}{path}"
            try:
                # Try POST with simple query
                resp = await client.post(
                    endpoint,
                    json={"query": "{__typename}"},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            found.append(endpoint)
                            continue
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")

                # Try GET
                resp = await client.get(
                    endpoint, params={"query": "{__typename}"}
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            found.append(endpoint)
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")

            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return found

    async def _introspect(
        self, client: httpx.AsyncClient, endpoint: str
    ) -> dict | None:
        """Send introspection query and return the schema."""
        # Try full introspection first
        for query in [INTROSPECTION_QUERY, SIMPLE_INTROSPECTION]:
            try:
                resp = await client.post(
                    endpoint,
                    json=query,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    schema = (data.get("data") or {}).get("__schema")
                    if schema and schema.get("types"):
                        return schema
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return None

    def _count_schema(self, schema: dict) -> tuple[int, int, int]:
        """Count types, fields, and mutations in schema."""
        types = schema.get("types", [])
        type_count = len([t for t in types if not t.get("name", "").startswith("__")])
        field_count = 0
        mutation_count = 0

        mutation_type_name = None
        mt = schema.get("mutationType")
        if mt:
            mutation_type_name = mt.get("name")

        for t in types:
            name = t.get("name", "")
            if name.startswith("__"):
                continue
            fields = t.get("fields") or []
            field_count += len(fields)
            if name == mutation_type_name:
                mutation_count = len(fields)

        return type_count, field_count, mutation_count

    def _analyze_sensitive_types(
        self, schema: dict, endpoint: str
    ) -> list[Finding]:
        """Check for types and fields that expose sensitive data."""
        findings: list[Finding] = []
        sensitive_items: list[str] = []

        for t in schema.get("types", []):
            type_name = t.get("name", "")
            if type_name.startswith("__"):
                continue

            if type_name.lower() in SENSITIVE_TYPE_NAMES:
                fields = t.get("fields") or []
                field_names = [f.get("name", "") for f in fields]
                sensitive_items.append(
                    f"Type '{type_name}' with fields: {', '.join(field_names[:10])}"
                )

            for field in t.get("fields") or []:
                field_name = field.get("name", "")
                if field_name.lower() in SENSITIVE_FIELD_NAMES:
                    sensitive_items.append(
                        f"Field '{type_name}.{field_name}'"
                    )

        if sensitive_items:
            findings.append(
                Finding(
                    title="Sensitive Data Types Exposed in GraphQL Schema",
                    severity=Severity.HIGH,
                    cvss_score=6.5,
                    description=(
                        "The GraphQL schema exposes types and fields that may contain "
                        "sensitive data. Attackers can craft queries to extract this information."
                    ),
                    evidence=(
                        f"Endpoint: {endpoint}\n"
                        f"Sensitive items ({len(sensitive_items)}):\n"
                        + "\n".join(f"  - {item}" for item in sensitive_items[:15])
                    ),
                    remediation=(
                        "Remove sensitive fields from the schema or add authorization checks. "
                        "Use field-level permissions. Never expose password hashes or secrets."
                    ),
                    category="graphql",
                )
            )

        return findings

    def _analyze_mutations(self, schema: dict, endpoint: str) -> list[Finding]:
        """Check for dangerous mutations in the schema."""
        findings: list[Finding] = []
        mutation_type_name = None
        mt = schema.get("mutationType")
        if mt:
            mutation_type_name = mt.get("name")
        if not mutation_type_name:
            return findings

        dangerous_found: list[str] = []
        for t in schema.get("types", []):
            if t.get("name") != mutation_type_name:
                continue
            for field in t.get("fields") or []:
                name = field.get("name", "")
                if any(d in name.lower() for d in DANGEROUS_MUTATIONS):
                    args = [a.get("name", "") for a in (field.get("args") or [])]
                    dangerous_found.append(f"{name}({', '.join(args)})")

        if dangerous_found:
            findings.append(
                Finding(
                    title="Potentially Dangerous GraphQL Mutations Exposed",
                    severity=Severity.MEDIUM,
                    cvss_score=5.4,
                    description=(
                        "The GraphQL schema exposes mutations that could be used for "
                        "privilege escalation, data manipulation, or account takeover."
                    ),
                    evidence=(
                        f"Endpoint: {endpoint}\n"
                        f"Dangerous mutations ({len(dangerous_found)}):\n"
                        + "\n".join(f"  - {m}" for m in dangerous_found[:15])
                    ),
                    remediation=(
                        "Implement proper authorization on all mutations. "
                        "Use role-based access control. Rate-limit sensitive mutations."
                    ),
                    category="graphql",
                )
            )

        return findings

    async def _test_unauth_mutations(
        self, client: httpx.AsyncClient, endpoint: str, schema: dict
    ) -> list[Finding]:
        """Test if mutations are accessible without authentication."""
        findings: list[Finding] = []
        mutation_type_name = None
        mt = schema.get("mutationType")
        if mt:
            mutation_type_name = mt.get("name")
        if not mutation_type_name:
            return findings

        for t in schema.get("types", []):
            if t.get("name") != mutation_type_name:
                continue
            for field in (t.get("fields") or [])[:5]:
                name = field.get("name", "")
                try:
                    # Send a minimal mutation probe
                    probe = {"query": f"mutation {{ {name} }}"}
                    resp = await client.post(
                        endpoint,
                        json=probe,
                        headers={"Content-Type": "application/json"},
                    )
                    data = resp.json()
                    errors = data.get("errors", [])
                    # If no auth error, mutation may be accessible
                    auth_keywords = {"unauthorized", "unauthenticated", "forbidden", "login", "permission"}
                    has_auth_error = any(
                        any(kw in str(e).lower() for kw in auth_keywords)
                        for e in errors
                    )
                    if not has_auth_error and "data" in data:
                        findings.append(
                            Finding(
                                title=f"Unauthenticated GraphQL Mutation Access: {name}",
                                severity=Severity.HIGH,
                                cvss_score=7.5,
                                description=(
                                    f"The mutation '{name}' appears accessible without authentication."
                                ),
                                evidence=(
                                    f"Endpoint: {endpoint}\n"
                                    f"Mutation: {name}\n"
                                    f"Response: {json.dumps(data)[:300]}"
                                ),
                                remediation=(
                                    "Require authentication for all mutations. "
                                    "Implement middleware-level auth checks."
                                ),
                                category="graphql",
                            )
                        )
                        break  # one finding is enough
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

        return findings
