"""Container and orchestration audit plugin.

Checks for exposed Docker daemons, Kubernetes API servers,
etcd, and kubelet endpoints that indicate container infrastructure
misconfigurations.
"""

import json
import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class ContainerAuditPlugin(ScannerPlugin):
    """Audit container infrastructure for exposed management APIs."""

    name = "container-audit"
    description = (
        "Check for exposed Docker daemon, Kubernetes API, etcd, "
        "and kubelet endpoints"
    )
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        host = target.ip or target.domain or target.host

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=10
            ) as client:
                # Docker daemon (HTTP)
                docker_findings = await self._check_docker(client, host)
                findings.extend(docker_findings)

                # Kubernetes API server
                k8s_findings = await self._check_kubernetes_api(client, host)
                findings.extend(k8s_findings)

                # Kubelet
                kubelet_findings = await self._check_kubelet(client, host)
                findings.extend(kubelet_findings)

                # etcd
                etcd_findings = await self._check_etcd(client, host)
                findings.extend(etcd_findings)

        except Exception as e:
            logger.error(f"[{self.name}] {e}")

        return findings

    # ------------------------------------------------------------------
    # Docker daemon
    # ------------------------------------------------------------------
    async def _check_docker(
        self, client: httpx.AsyncClient, host: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for port in (2375, 2376):
            scheme = "https" if port == 2376 else "http"
            base = f"{scheme}://{host}:{port}"

            # Check /version endpoint
            try:
                resp = await client.get(f"{base}/version")
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        api_version = data.get("ApiVersion", "unknown")
                        os_name = data.get("Os", "unknown")
                        docker_version = data.get("Version", "unknown")

                        findings.append(Finding(
                            title=f"Docker daemon exposed on port {port}",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            description=(
                                f"The Docker daemon API is accessible without authentication "
                                f"on port {port}. An attacker can create privileged containers, "
                                "escape to the host, read/write arbitrary files, and achieve "
                                "full host compromise."
                            ),
                            evidence=(
                                f"URL: {base}/version\n"
                                f"Docker version: {docker_version}\n"
                                f"API version: {api_version}\n"
                                f"OS: {os_name}"
                            ),
                            remediation=(
                                "Disable TCP socket access to the Docker daemon. Use Unix "
                                "socket with proper permissions. If remote access is needed, "
                                "configure TLS mutual authentication."
                            ),
                            category="container",
                            references=[
                                "https://docs.docker.com/engine/security/protect-access/",
                            ],
                            metadata={
                                "port": port,
                                "docker_version": docker_version,
                                "api_version": api_version,
                            },
                        ))
                    except (json.JSONDecodeError, ValueError):
                        pass
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

            # Check /containers/json - list running containers
            try:
                resp = await client.get(f"{base}/containers/json")
                if resp.status_code == 200:
                    try:
                        containers = resp.json()
                        if isinstance(containers, list):
                            container_names = []
                            privileged_containers = []
                            for c in containers:
                                names = c.get("Names", [])
                                name_str = ", ".join(names) if names else c.get("Id", "")[:12]
                                container_names.append(name_str)
                                # Check for privileged mode indicators
                                host_config = c.get("HostConfig", {})
                                if host_config.get("Privileged"):
                                    privileged_containers.append(name_str)

                            findings.append(Finding(
                                title=f"Docker API lists {len(containers)} running container(s)",
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                description=(
                                    "Unauthenticated access to the Docker container listing. "
                                    "Attacker can inspect, stop, start, and exec into containers."
                                ),
                                evidence=(
                                    f"URL: {base}/containers/json\n"
                                    f"Running containers: {len(containers)}\n"
                                    f"Names: {'; '.join(container_names[:10])}"
                                ),
                                remediation="Restrict Docker daemon access. See Docker security documentation.",
                                category="container",
                                metadata={
                                    "container_count": len(containers),
                                    "containers": container_names[:20],
                                },
                            ))

                            if privileged_containers:
                                findings.append(Finding(
                                    title=f"Privileged containers detected ({len(privileged_containers)})",
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.8,
                                    description=(
                                        "Privileged containers have full access to the host system, "
                                        "including all devices and kernel capabilities."
                                    ),
                                    evidence=f"Privileged containers: {', '.join(privileged_containers)}",
                                    remediation=(
                                        "Avoid running containers in privileged mode. Use specific "
                                        "capabilities (--cap-add) instead."
                                    ),
                                    category="container",
                                ))
                    except (json.JSONDecodeError, ValueError):
                        pass
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

            # Check /images/json - list images
            try:
                resp = await client.get(f"{base}/images/json")
                if resp.status_code == 200:
                    try:
                        images = resp.json()
                        if isinstance(images, list) and images:
                            image_tags = []
                            for img in images[:15]:
                                tags = img.get("RepoTags", [])
                                if tags:
                                    image_tags.extend(tags)

                            findings.append(Finding(
                                title=f"Docker API exposes {len(images)} image(s)",
                                severity=Severity.HIGH,
                                cvss_score=7.5,
                                description=(
                                    "Unauthenticated access to the Docker image listing. "
                                    "Reveals infrastructure details and potentially "
                                    "proprietary images."
                                ),
                                evidence=(
                                    f"URL: {base}/images/json\n"
                                    f"Images: {len(images)}\n"
                                    f"Tags: {'; '.join(image_tags[:10])}"
                                ),
                                remediation="Restrict Docker daemon access.",
                                category="container",
                                metadata={"image_count": len(images)},
                            ))
                    except (json.JSONDecodeError, ValueError):
                        pass
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return findings

    # ------------------------------------------------------------------
    # Kubernetes API server
    # ------------------------------------------------------------------
    async def _check_kubernetes_api(
        self, client: httpx.AsyncClient, host: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for port in (6443, 8443, 443):
            base = f"https://{host}:{port}"

            # /version endpoint
            try:
                resp = await client.get(f"{base}/version")
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        k8s_version = data.get("gitVersion", "unknown")
                        platform = data.get("platform", "unknown")

                        findings.append(Finding(
                            title=f"Kubernetes API server exposed on port {port}",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            description=(
                                "The Kubernetes API server is accessible and responds to "
                                "unauthenticated /version requests. Depending on RBAC "
                                "configuration, anonymous access may allow full cluster "
                                "compromise."
                            ),
                            evidence=(
                                f"URL: {base}/version\n"
                                f"Kubernetes version: {k8s_version}\n"
                                f"Platform: {platform}"
                            ),
                            remediation=(
                                "Restrict Kubernetes API access with network policies and "
                                "firewall rules. Disable anonymous authentication. Enforce "
                                "RBAC policies."
                            ),
                            category="container",
                            references=[
                                "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
                            ],
                            metadata={
                                "port": port,
                                "k8s_version": k8s_version,
                                "platform": platform,
                            },
                        ))
                    except (json.JSONDecodeError, ValueError):
                        pass
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

            # Check if we can list pods (anonymous access)
            try:
                resp = await client.get(f"{base}/api/v1/pods")
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        pod_count = len(data.get("items", []))
                        findings.append(Finding(
                            title=f"Kubernetes pods listing accessible anonymously ({pod_count} pods)",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            description=(
                                "Anonymous users can list all pods in the cluster, "
                                "revealing the full application topology and potentially "
                                "secrets mounted in pods."
                            ),
                            evidence=f"URL: {base}/api/v1/pods\nPod count: {pod_count}",
                            remediation="Disable anonymous access and enforce RBAC.",
                            category="container",
                        ))
                    except (json.JSONDecodeError, ValueError):
                        pass
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

            # Check /api/v1/secrets
            try:
                resp = await client.get(f"{base}/api/v1/secrets")
                if resp.status_code == 200:
                    findings.append(Finding(
                        title="Kubernetes secrets accessible anonymously",
                        severity=Severity.CRITICAL,
                        cvss_score=10.0,
                        description=(
                            "Anonymous users can list all secrets in the cluster. "
                            "This exposes credentials, tokens, and certificates."
                        ),
                        evidence=f"URL: {base}/api/v1/secrets returns HTTP 200",
                        remediation="Disable anonymous access and restrict RBAC immediately.",
                        category="container",
                    ))
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return findings

    # ------------------------------------------------------------------
    # Kubelet
    # ------------------------------------------------------------------
    async def _check_kubelet(
        self, client: httpx.AsyncClient, host: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for port in (10250, 10255):
            scheme = "https" if port == 10250 else "http"
            base = f"{scheme}://{host}:{port}"

            # /pods or /runningpods
            for endpoint in ("/runningpods", "/pods"):
                try:
                    resp = await client.get(f"{base}{endpoint}")
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            items = data.get("items", [])
                            pod_names = [
                                p.get("metadata", {}).get("name", "unknown")
                                for p in items[:10]
                            ]

                            findings.append(Finding(
                                title=f"Kubelet API exposed on port {port} ({endpoint})",
                                severity=Severity.HIGH,
                                cvss_score=8.6,
                                description=(
                                    f"The Kubelet API endpoint {endpoint} is accessible on "
                                    f"port {port}. This can be used to exec into containers "
                                    "and access sensitive pod information."
                                ),
                                evidence=(
                                    f"URL: {base}{endpoint}\n"
                                    f"Pods found: {len(items)}\n"
                                    f"Sample: {', '.join(pod_names)}"
                                ),
                                remediation=(
                                    "Disable anonymous Kubelet authentication. Set "
                                    "--anonymous-auth=false and use webhook authentication."
                                ),
                                category="container",
                                references=[
                                    "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/",
                                ],
                                metadata={"port": port, "endpoint": endpoint},
                            ))
                            break  # Found one endpoint, skip the other
                        except (json.JSONDecodeError, ValueError):
                            pass
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

        return findings

    # ------------------------------------------------------------------
    # etcd
    # ------------------------------------------------------------------
    async def _check_etcd(
        self, client: httpx.AsyncClient, host: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for port in (2379, 2380):
            base = f"http://{host}:{port}"

            # /version endpoint
            try:
                resp = await client.get(f"{base}/version")
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        etcd_version = data.get("etcdserver", "unknown")
                        cluster_version = data.get("etcdcluster", "unknown")

                        findings.append(Finding(
                            title=f"etcd server exposed on port {port}",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            description=(
                                "The etcd key-value store is accessible without authentication. "
                                "In Kubernetes clusters, etcd stores all cluster data including "
                                "secrets, configurations, and service account tokens."
                            ),
                            evidence=(
                                f"URL: {base}/version\n"
                                f"etcd version: {etcd_version}\n"
                                f"Cluster version: {cluster_version}"
                            ),
                            remediation=(
                                "Restrict etcd access with firewall rules. Enable TLS mutual "
                                "authentication. Never expose etcd to untrusted networks."
                            ),
                            category="container",
                            references=[
                                "https://etcd.io/docs/v3.5/op-guide/security/",
                            ],
                            metadata={
                                "port": port,
                                "etcd_version": etcd_version,
                            },
                        ))
                    except (json.JSONDecodeError, ValueError):
                        pass
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

            # Try to list keys (etcd v2 API)
            try:
                resp = await client.get(f"{base}/v2/keys/?recursive=true")
                if resp.status_code == 200:
                    findings.append(Finding(
                        title=f"etcd v2 API keys accessible on port {port}",
                        severity=Severity.CRITICAL,
                        cvss_score=10.0,
                        description=(
                            "The etcd v2 keys API is accessible, allowing anyone to read "
                            "and write cluster state including secrets."
                        ),
                        evidence=f"URL: {base}/v2/keys/?recursive=true returns HTTP 200",
                        remediation="Restrict etcd access immediately. Enable authentication.",
                        category="container",
                    ))
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

            # etcd v3 health
            try:
                resp = await client.get(f"{base}/health")
                if resp.status_code == 200 and "true" in resp.text.lower():
                    # Only report health if we didn't already get /version
                    has_version = any(
                        f"etcd server exposed on port {port}" in f.title
                        for f in findings
                    )
                    if not has_version:
                        findings.append(Finding(
                            title=f"etcd health endpoint accessible on port {port}",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description="The etcd health endpoint is accessible, confirming etcd presence.",
                            evidence=f"URL: {base}/health returns healthy status",
                            remediation="Restrict network access to etcd.",
                            category="container",
                        ))
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return findings
