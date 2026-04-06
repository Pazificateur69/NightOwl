"""CI/CD pipeline security audit plugin.

Checks for exposed CI/CD management interfaces including Jenkins,
GitLab, Drone CI, ArgoCD, and SonarQube. Also checks for default
credentials and exposed configuration files.
"""

import base64
import json
import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class CICDAuditPlugin(ScannerPlugin):
    """Audit CI/CD systems for exposed interfaces and misconfigurations."""

    name = "cicd-audit"
    description = (
        "Check for exposed CI/CD interfaces (Jenkins, GitLab, Drone, ArgoCD, "
        "SonarQube), default credentials, and leaked config files"
    )
    version = "1.0.0"
    stage = "scan"

    def _resolve_base_url(self, target: Target) -> str:
        if target.url:
            return target.url.rstrip("/")
        scheme = "https" if target.port in (443, 8443, None) else "http"
        host = target.domain or target.ip or target.host
        port_part = "" if target.port in (80, 443, None) else f":{target.port}"
        return f"{scheme}://{host}{port_part}"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        base_url = self._resolve_base_url(target)
        host = target.ip or target.domain or target.host

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=10
            ) as client:
                # Jenkins
                jenkins_findings = await self._check_jenkins(client, base_url)
                findings.extend(jenkins_findings)

                # GitLab
                gitlab_findings = await self._check_gitlab(client, base_url)
                findings.extend(gitlab_findings)

                # Drone CI
                drone_findings = await self._check_drone(client, base_url)
                findings.extend(drone_findings)

                # ArgoCD
                argo_findings = await self._check_argocd(client, base_url)
                findings.extend(argo_findings)

                # SonarQube
                sonar_findings = await self._check_sonarqube(client, base_url)
                findings.extend(sonar_findings)

                # GitHub Actions workflow files (via web)
                gh_findings = await self._check_github_workflows(client, base_url)
                findings.extend(gh_findings)

                # Exposed config files
                config_findings = await self._check_exposed_configs(client, base_url)
                findings.extend(config_findings)

        except Exception as e:
            logger.error(f"[{self.name}] {e}")

        return findings

    # ------------------------------------------------------------------
    # Jenkins
    # ------------------------------------------------------------------
    async def _check_jenkins(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        is_jenkins = False

        # Check /login page
        try:
            resp = await client.get(f"{base_url}/login")
            if resp.status_code == 200 and "jenkins" in resp.text.lower():
                is_jenkins = True
                findings.append(Finding(
                    title="Jenkins login page accessible",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description="Jenkins CI/CD login page is publicly accessible.",
                    evidence=f"URL: {base_url}/login (HTTP 200)",
                    remediation=(
                        "Restrict Jenkins access to internal networks. Use VPN or "
                        "IP whitelisting. Enable authentication and authorization."
                    ),
                    category="cicd",
                    metadata={"tool": "jenkins"},
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check /api/json (unauthenticated API access)
        try:
            resp = await client.get(f"{base_url}/api/json")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    jobs = data.get("jobs", [])
                    job_names = [j.get("name", "") for j in jobs[:10]]

                    findings.append(Finding(
                        title=f"Jenkins API accessible without authentication ({len(jobs)} jobs)",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description=(
                            "Jenkins API is accessible without authentication, exposing "
                            "job configurations, build history, and credentials."
                        ),
                        evidence=(
                            f"URL: {base_url}/api/json\n"
                            f"Jobs found: {len(jobs)}\n"
                            f"Sample jobs: {', '.join(job_names)}"
                        ),
                        remediation=(
                            "Enable Jenkins security. Configure authentication and "
                            "authorization strategies. Disable anonymous read access."
                        ),
                        category="cicd",
                        metadata={"tool": "jenkins", "job_count": len(jobs)},
                    ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check /script (Groovy script console - CRITICAL)
        try:
            resp = await client.get(f"{base_url}/script")
            if resp.status_code == 200 and ("groovy" in resp.text.lower() or "script console" in resp.text.lower()):
                findings.append(Finding(
                    title="Jenkins Groovy script console accessible",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    description=(
                        "The Jenkins Groovy script console is accessible. This allows "
                        "arbitrary code execution on the Jenkins server, leading to "
                        "full system compromise."
                    ),
                    evidence=f"URL: {base_url}/script (HTTP 200, Groovy console detected)",
                    remediation=(
                        "Restrict script console access to admins only. Disable for "
                        "anonymous users. Consider using Matrix Authorization."
                    ),
                    category="cicd",
                    references=[
                        "https://www.jenkins.io/doc/book/managing/script-console/",
                    ],
                    metadata={"tool": "jenkins"},
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check /env (environment variables)
        try:
            resp = await client.get(f"{base_url}/env")
            if resp.status_code == 200 and ("environment" in resp.text.lower() or "PATH" in resp.text):
                findings.append(Finding(
                    title="Jenkins environment variables exposed",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    description=(
                        "Jenkins environment variables are accessible, potentially "
                        "exposing secrets, API keys, and system paths."
                    ),
                    evidence=f"URL: {base_url}/env (HTTP 200)",
                    remediation="Restrict access to Jenkins environment information.",
                    category="cicd",
                    metadata={"tool": "jenkins"},
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check default credentials (admin/admin)
        if is_jenkins:
            try:
                resp = await client.post(
                    f"{base_url}/j_spring_security_check",
                    data={"j_username": "admin", "j_password": "admin"},
                    follow_redirects=False,
                )
                # Successful login typically redirects to / without loginError
                if resp.status_code in (301, 302):
                    location = resp.headers.get("location", "")
                    if "loginError" not in location and "login" not in location.lower():
                        findings.append(Finding(
                            title="Jenkins default credentials (admin/admin)",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            description=(
                                "Jenkins accepts default admin credentials (admin/admin). "
                                "This grants full administrative access to the CI/CD system."
                            ),
                            evidence=f"Login with admin/admin redirects to: {location}",
                            remediation="Change the default admin password immediately.",
                            category="cicd",
                            metadata={"tool": "jenkins"},
                        ))
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")

        return findings

    # ------------------------------------------------------------------
    # GitLab
    # ------------------------------------------------------------------
    async def _check_gitlab(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Health check
        try:
            resp = await client.get(f"{base_url}/-/health")
            if resp.status_code == 200 and "gitlab" in resp.text.lower():
                findings.append(Finding(
                    title="GitLab instance detected (health endpoint)",
                    severity=Severity.INFO,
                    description="GitLab health endpoint is accessible.",
                    evidence=f"URL: {base_url}/-/health (HTTP 200)",
                    category="cicd",
                    metadata={"tool": "gitlab"},
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Public explore page (indicates public access is enabled)
        try:
            resp = await client.get(f"{base_url}/explore")
            if resp.status_code == 200 and ("gitlab" in resp.text.lower() or "projects" in resp.text.lower()):
                findings.append(Finding(
                    title="GitLab public explore page accessible",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        "The GitLab explore page is publicly accessible, allowing "
                        "unauthenticated users to browse public projects, groups, "
                        "and snippets."
                    ),
                    evidence=f"URL: {base_url}/explore (HTTP 200)",
                    remediation=(
                        "Restrict public access if GitLab is intended for internal use. "
                        "Disable public project visibility and sign-up."
                    ),
                    category="cicd",
                    metadata={"tool": "gitlab"},
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Public API (projects listing)
        try:
            resp = await client.get(f"{base_url}/api/v4/projects?per_page=5")
            if resp.status_code == 200:
                try:
                    projects = resp.json()
                    if isinstance(projects, list) and projects:
                        project_names = [
                            p.get("path_with_namespace", "")
                            for p in projects[:5]
                        ]
                        findings.append(Finding(
                            title=f"GitLab API exposes public projects ({len(projects)}+ found)",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            description=(
                                "The GitLab API returns project information without "
                                "authentication."
                            ),
                            evidence=(
                                f"URL: {base_url}/api/v4/projects\n"
                                f"Sample projects: {', '.join(project_names)}"
                            ),
                            remediation="Restrict public API access and project visibility.",
                            category="cicd",
                            metadata={"tool": "gitlab"},
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check if user registration is open
        try:
            resp = await client.get(f"{base_url}/users/sign_up")
            if resp.status_code == 200 and "sign_up" in resp.text.lower():
                findings.append(Finding(
                    title="GitLab user registration is open",
                    severity=Severity.HIGH,
                    cvss_score=7.3,
                    description=(
                        "GitLab user registration is enabled, allowing anyone to "
                        "create an account and potentially access internal repositories."
                    ),
                    evidence=f"URL: {base_url}/users/sign_up (HTTP 200)",
                    remediation="Disable public user registration in GitLab admin settings.",
                    category="cicd",
                    metadata={"tool": "gitlab"},
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return findings

    # ------------------------------------------------------------------
    # Drone CI
    # ------------------------------------------------------------------
    async def _check_drone(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # /api/user (unauthenticated check)
        try:
            resp = await client.get(f"{base_url}/api/user")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    login = data.get("login", "unknown")
                    findings.append(Finding(
                        title=f"Drone CI API accessible (user: {login})",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description=(
                            "Drone CI user API is accessible without proper authentication."
                        ),
                        evidence=f"URL: {base_url}/api/user\nUser: {login}",
                        remediation="Configure authentication for the Drone CI API.",
                        category="cicd",
                        metadata={"tool": "drone"},
                    ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # /api/repos
        try:
            resp = await client.get(f"{base_url}/api/repos")
            if resp.status_code == 200:
                try:
                    repos = resp.json()
                    if isinstance(repos, list) and repos:
                        repo_names = [
                            r.get("full_name", r.get("slug", ""))
                            for r in repos[:10]
                        ]
                        findings.append(Finding(
                            title=f"Drone CI repos accessible ({len(repos)} repos)",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=(
                                "Drone CI repository list is accessible without "
                                "authentication, exposing CI/CD pipeline information."
                            ),
                            evidence=(
                                f"URL: {base_url}/api/repos\n"
                                f"Repos: {', '.join(repo_names)}"
                            ),
                            remediation="Restrict Drone CI API access. Enable authentication.",
                            category="cicd",
                            metadata={"tool": "drone", "repo_count": len(repos)},
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return findings

    # ------------------------------------------------------------------
    # ArgoCD
    # ------------------------------------------------------------------
    async def _check_argocd(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # /api/v1/applications
        try:
            resp = await client.get(f"{base_url}/api/v1/applications")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    items = data.get("items", [])
                    app_names = [
                        a.get("metadata", {}).get("name", "")
                        for a in items[:10]
                    ]
                    findings.append(Finding(
                        title=f"ArgoCD API accessible ({len(items)} applications)",
                        severity=Severity.CRITICAL,
                        cvss_score=9.0,
                        description=(
                            "ArgoCD applications API is accessible without authentication. "
                            "An attacker can view, modify, or sync Kubernetes deployments."
                        ),
                        evidence=(
                            f"URL: {base_url}/api/v1/applications\n"
                            f"Applications: {', '.join(app_names)}"
                        ),
                        remediation=(
                            "Enable ArgoCD authentication. Use SSO/OIDC. Restrict API "
                            "access with network policies."
                        ),
                        category="cicd",
                        references=[
                            "https://argo-cd.readthedocs.io/en/stable/operator-manual/security/",
                        ],
                        metadata={"tool": "argocd", "app_count": len(items)},
                    ))
                except (json.JSONDecodeError, ValueError):
                    pass
            elif resp.status_code == 401:
                # ArgoCD is present but requires auth
                findings.append(Finding(
                    title="ArgoCD instance detected",
                    severity=Severity.INFO,
                    description="ArgoCD is running and requires authentication.",
                    evidence=f"URL: {base_url}/api/v1/applications returns 401",
                    category="cicd",
                    metadata={"tool": "argocd"},
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # /api/version
        try:
            resp = await client.get(f"{base_url}/api/version")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    argo_version = data.get("Version", "unknown")
                    findings.append(Finding(
                        title=f"ArgoCD version disclosed: {argo_version}",
                        severity=Severity.INFO,
                        description=f"ArgoCD version {argo_version} identified.",
                        evidence=f"URL: {base_url}/api/version\nVersion: {argo_version}",
                        category="cicd",
                        metadata={"tool": "argocd", "version": argo_version},
                    ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return findings

    # ------------------------------------------------------------------
    # SonarQube
    # ------------------------------------------------------------------
    async def _check_sonarqube(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # /api/system/status
        try:
            resp = await client.get(f"{base_url}/api/system/status")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    status = data.get("status", "unknown")
                    version = data.get("version", "unknown")

                    findings.append(Finding(
                        title=f"SonarQube instance detected (v{version}, status: {status})",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description=(
                            "SonarQube system status API is accessible, disclosing "
                            "version and operational status."
                        ),
                        evidence=(
                            f"URL: {base_url}/api/system/status\n"
                            f"Version: {version}\n"
                            f"Status: {status}"
                        ),
                        remediation=(
                            "Restrict SonarQube access to internal networks. "
                            "Require authentication for API access."
                        ),
                        category="cicd",
                        metadata={"tool": "sonarqube", "version": version},
                    ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check for public projects
        try:
            resp = await client.get(f"{base_url}/api/projects/search?ps=5")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    components = data.get("components", [])
                    if components:
                        project_keys = [c.get("key", "") for c in components[:5]]
                        findings.append(Finding(
                            title=f"SonarQube projects accessible ({data.get('paging', {}).get('total', len(components))} total)",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=(
                                "SonarQube projects are accessible without authentication. "
                                "This exposes code quality data, security hotspots, and "
                                "vulnerability information."
                            ),
                            evidence=(
                                f"URL: {base_url}/api/projects/search\n"
                                f"Projects: {', '.join(project_keys)}"
                            ),
                            remediation="Enable force authentication in SonarQube settings.",
                            category="cicd",
                            metadata={"tool": "sonarqube"},
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return findings

    # ------------------------------------------------------------------
    # GitHub Actions workflow files
    # ------------------------------------------------------------------
    async def _check_github_workflows(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Check if /.github/workflows/ is browsable
        try:
            resp = await client.get(f"{base_url}/.github/workflows/")
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                if ".yml" in body_lower or ".yaml" in body_lower or "index of" in body_lower:
                    findings.append(Finding(
                        title="GitHub Actions workflow directory exposed",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description=(
                            "The .github/workflows/ directory is accessible via the web "
                            "server, exposing CI/CD pipeline definitions and potentially "
                            "secrets references."
                        ),
                        evidence=f"URL: {base_url}/.github/workflows/ (HTTP 200)",
                        remediation="Block access to .github/ directory in web server configuration.",
                        category="cicd",
                    ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return findings

    # ------------------------------------------------------------------
    # Exposed configuration files
    # ------------------------------------------------------------------
    async def _check_exposed_configs(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        config_checks = [
            {
                "path": "/.env",
                "indicators": ["DB_PASSWORD", "APP_KEY", "SECRET_KEY", "API_KEY", "AWS_"],
                "title": "Environment file (.env) exposed",
                "severity": Severity.CRITICAL,
                "cvss": 9.8,
                "description": (
                    "The .env file is publicly accessible, potentially exposing "
                    "database credentials, API keys, and other secrets."
                ),
            },
            {
                "path": "/.git/config",
                "indicators": ["[core]", "[remote", "repositoryformatversion"],
                "title": "Git configuration (.git/config) exposed",
                "severity": Severity.HIGH,
                "cvss": 7.5,
                "description": (
                    "The .git/config file is accessible, exposing repository "
                    "configuration and potentially remote URLs with credentials."
                ),
            },
            {
                "path": "/.gitlab-ci.yml",
                "indicators": ["stages:", "script:", "image:", "variables:"],
                "title": "GitLab CI configuration (.gitlab-ci.yml) exposed",
                "severity": Severity.HIGH,
                "cvss": 7.5,
                "description": (
                    "The GitLab CI configuration file is publicly accessible, "
                    "exposing pipeline definitions, deployment secrets, and "
                    "infrastructure details."
                ),
            },
            {
                "path": "/Jenkinsfile",
                "indicators": ["pipeline", "agent", "stages", "steps"],
                "title": "Jenkinsfile exposed",
                "severity": Severity.MEDIUM,
                "cvss": 5.3,
                "description": (
                    "The Jenkinsfile is publicly accessible, exposing CI/CD "
                    "pipeline configuration."
                ),
            },
            {
                "path": "/.github/workflows/ci.yml",
                "indicators": ["on:", "jobs:", "runs-on:", "steps:"],
                "title": "GitHub Actions workflow file exposed",
                "severity": Severity.MEDIUM,
                "cvss": 5.3,
                "description": (
                    "A GitHub Actions workflow file is publicly accessible."
                ),
            },
            {
                "path": "/docker-compose.yml",
                "indicators": ["services:", "image:", "volumes:", "ports:"],
                "title": "Docker Compose file exposed",
                "severity": Severity.HIGH,
                "cvss": 7.5,
                "description": (
                    "The docker-compose.yml file is publicly accessible, revealing "
                    "service architecture, ports, volumes, and potentially secrets."
                ),
            },
        ]

        for check in config_checks:
            try:
                resp = await client.get(f"{base_url}{check['path']}")
                if resp.status_code == 200 and len(resp.text) > 10:
                    content = resp.text[:2000]
                    matched_indicators = [
                        ind for ind in check["indicators"]
                        if ind in content
                    ]
                    if matched_indicators:
                        findings.append(Finding(
                            title=check["title"],
                            severity=check["severity"],
                            cvss_score=check["cvss"],
                            description=check["description"],
                            evidence=(
                                f"URL: {base_url}{check['path']}\n"
                                f"Matched indicators: {', '.join(matched_indicators)}"
                            ),
                            remediation=(
                                f"Block access to {check['path']} in web server "
                                "configuration using deny rules."
                            ),
                            category="cicd-config-exposure",
                        ))
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return findings
