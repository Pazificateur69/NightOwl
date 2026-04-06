"""Dependency confusion attack surface scanner."""

import asyncio
import json
import logging
import re
from urllib.parse import urljoin

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Paths to spider for manifest files
MANIFEST_PATHS = [
    "/package.json",
    "/.package.json",
    "/assets/package.json",
    "/static/package.json",
    "/js/package.json",
    "/app/package.json",
    "/src/package.json",
    "/node_modules/.package-lock.json",
    "/requirements.txt",
    "/.requirements.txt",
    "/requirements/base.txt",
    "/requirements/prod.txt",
    "/Gemfile",
    "/Gemfile.lock",
    "/go.mod",
    "/go.sum",
    "/pom.xml",
    "/composer.json",
    "/Pipfile",
    "/Pipfile.lock",
    "/pyproject.toml",
    "/yarn.lock",
    "/package-lock.json",
]


def _extract_npm_packages(text: str) -> list[str]:
    """Extract package names from package.json content."""
    packages: set[str] = set()
    try:
        data = json.loads(text)
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = data.get(key, {})
            if isinstance(deps, dict):
                packages.update(deps.keys())
    except (json.JSONDecodeError, TypeError):
        pass
    return list(packages)


def _extract_pypi_packages(text: str) -> list[str]:
    """Extract package names from requirements.txt."""
    packages: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        # Strip version specifiers
        match = re.match(r"^([A-Za-z0-9._-]+)", line)
        if match:
            packages.append(match.group(1))
    return packages


def _extract_pyproject_packages(text: str) -> list[str]:
    """Extract dependency names from pyproject.toml.

    Handles both PEP 621 [project.dependencies] and Poetry
    [tool.poetry.dependencies] formats using simple regex parsing
    (no TOML library required).
    """
    packages: list[str] = []

    # PEP 621: dependencies = ["requests>=2.0", "click"]
    # Match the dependencies array
    dep_match = re.search(
        r'\[project\]\s*\n(?:.*\n)*?dependencies\s*=\s*\[(.*?)\]',
        text, re.DOTALL
    )
    if dep_match:
        array_content = dep_match.group(1)
        for item in re.findall(r'"([^"]+)"', array_content):
            name_match = re.match(r'^([A-Za-z0-9._-]+)', item)
            if name_match:
                packages.append(name_match.group(1))

    # Also check optional-dependencies
    for opt_match in re.finditer(
        r'\[project\.optional-dependencies\]\s*\n((?:.*\n)*?(?=\[|\Z))',
        text
    ):
        section = opt_match.group(1)
        for item in re.findall(r'"([^"]+)"', section):
            name_match = re.match(r'^([A-Za-z0-9._-]+)', item)
            if name_match:
                pkg = name_match.group(1)
                if pkg not in packages:
                    packages.append(pkg)

    # Poetry: [tool.poetry.dependencies] section with key = "version"
    poetry_match = re.search(
        r'\[tool\.poetry\.dependencies\]\s*\n((?:.*\n)*?(?=\[|\Z))',
        text
    )
    if poetry_match:
        section = poetry_match.group(1)
        for line in section.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key_match = re.match(r'^([A-Za-z0-9._-]+)\s*=', line)
            if key_match:
                pkg = key_match.group(1)
                if pkg.lower() != "python" and pkg not in packages:
                    packages.append(pkg)

    return packages


def _extract_gemfile_packages(text: str) -> list[str]:
    """Extract gem names from Gemfile."""
    packages: list[str] = []
    for line in text.splitlines():
        match = re.match(r"""^\s*gem\s+['"]([^'"]+)['"]""", line)
        if match:
            packages.append(match.group(1))
    return packages


def _extract_gomod_packages(text: str) -> list[str]:
    """Extract module paths from go.mod."""
    packages: list[str] = []
    in_require = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require:
            if line == ")":
                in_require = False
                continue
            parts = line.split()
            if parts:
                packages.append(parts[0])
        elif line.startswith("require "):
            parts = line.split()
            if len(parts) >= 2:
                packages.append(parts[1])
    return packages


def _extract_pom_packages(text: str) -> list[str]:
    """Extract artifact IDs from pom.xml (simple regex, no XML parser needed)."""
    packages: list[str] = []
    for match in re.finditer(r"<artifactId>([^<]+)</artifactId>", text):
        artifact = match.group(1).strip()
        if artifact and artifact not in packages:
            packages.append(artifact)
    return packages


# Manifest file -> (extractor, registry_type)
EXTRACTORS = {
    "package.json": (_extract_npm_packages, "npm"),
    "package-lock.json": (_extract_npm_packages, "npm"),
    "requirements.txt": (_extract_pypi_packages, "pypi"),
    "base.txt": (_extract_pypi_packages, "pypi"),
    "prod.txt": (_extract_pypi_packages, "pypi"),
    "Pipfile": (_extract_pypi_packages, "pypi"),
    "pyproject.toml": (_extract_pyproject_packages, "pypi"),
    "Gemfile": (_extract_gemfile_packages, "rubygems"),
    "Gemfile.lock": (_extract_gemfile_packages, "rubygems"),
    "go.mod": (_extract_gomod_packages, "go"),
    "go.sum": (_extract_gomod_packages, "go"),
    "pom.xml": (_extract_pom_packages, "maven"),
    "composer.json": (_extract_npm_packages, "packagist"),  # same JSON structure
}


class DependencyConfusionPlugin(ScannerPlugin):
    name = "dependency-confusion"
    description = "Detect dependency confusion attack vectors in exposed manifests"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        base_url = target.url or f"https://{target.host}"

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=10,
        ) as client:
            # Phase 1: Spider for manifest files
            discovered: list[dict] = []
            discovered_paths: list[str] = []
            for path in MANIFEST_PATHS:
                url = urljoin(base_url, path)
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        filename = path.rstrip("/").split("/")[-1]
                        discovered.append({
                            "url": url,
                            "filename": filename,
                            "content": resp.text,
                        })
                        discovered_paths.append(path)
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

                await asyncio.sleep(0.05)

            # Report all exposed manifests in a single consolidated finding
            if discovered_paths:
                findings.append(Finding(
                    title=f"Exposed manifest files ({len(discovered_paths)} found)",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        f"Package manifest files are publicly accessible on {base_url}. "
                        f"These files reveal internal dependency information."
                    ),
                    evidence="Exposed paths:\n" + "\n".join(
                        f"  - {d['url']} ({len(d['content'])} bytes)" for d in discovered
                    ),
                    remediation="Remove or restrict access to manifest files in production. Use .htaccess or server config.",
                    category="dependency-confusion",
                ))

            if not discovered:
                logger.info("No manifest files found")
                return findings

            # Phase 2: Extract package names
            all_packages: dict[str, str] = {}  # package -> registry_type
            for doc in discovered:
                filename = doc["filename"]
                for key, (extractor, registry) in EXTRACTORS.items():
                    if filename.endswith(key) or filename == key:
                        packages = extractor(doc["content"])
                        for pkg in packages:
                            if pkg not in all_packages:
                                all_packages[pkg] = registry
                        break

            if not all_packages:
                logger.info("No packages extracted from manifests")
                return findings

            logger.info(f"Extracted {len(all_packages)} unique package names, checking public registries")

            # Phase 3: Check if packages exist on public registries
            confusion_candidates: list[dict] = []

            sem = asyncio.Semaphore(10)

            async def check_package(name: str, registry: str) -> None:
                async with sem:
                    exists = await self._check_public_registry(client, name, registry)
                    if not exists:
                        confusion_candidates.append({
                            "package": name,
                            "registry": registry,
                        })
                    await asyncio.sleep(0.05)

            tasks = []
            for pkg, reg in all_packages.items():
                # Only check npm and PyPI (most common confusion targets)
                if reg in ("npm", "pypi"):
                    tasks.append(check_package(pkg, reg))

            if tasks:
                await asyncio.gather(*tasks)

            # Phase 4: Report confusion candidates
            for candidate in confusion_candidates:
                findings.append(Finding(
                    title=f"Dependency confusion target: {candidate['package']} ({candidate['registry']})",
                    severity=Severity.HIGH,
                    cvss_score=8.0,
                    description=(
                        f"Package '{candidate['package']}' is referenced in a manifest but does not "
                        f"exist on the public {candidate['registry']} registry. An attacker could "
                        f"register this name on the public registry to execute a dependency confusion attack."
                    ),
                    evidence=(
                        f"Package: {candidate['package']}\n"
                        f"Registry: {candidate['registry']}\n"
                        f"Public registry check: NOT FOUND\n"
                        f"Attack: Register '{candidate['package']}' on public "
                        f"{candidate['registry']} with malicious code"
                    ),
                    remediation=(
                        "Pin dependencies to exact versions. Use registry scoping (@org/package). "
                        "Register placeholder packages on public registries. "
                        "Use .npmrc or pip.conf to restrict to private registry."
                    ),
                    category="dependency-confusion",
                    metadata={
                        "package": candidate["package"],
                        "registry": candidate["registry"],
                        "vuln": "dependency_confusion",
                    },
                ))

        return findings

    async def _check_public_registry(
        self,
        client: httpx.AsyncClient,
        package: str,
        registry: str,
    ) -> bool:
        """Return True if the package exists on the public registry."""
        try:
            if registry == "npm":
                url = f"https://registry.npmjs.org/{package}"
                resp = await client.get(url)
                return resp.status_code == 200

            elif registry == "pypi":
                url = f"https://pypi.org/pypi/{package}/json"
                resp = await client.get(url)
                return resp.status_code == 200

        except Exception as e:
            logger.debug(f"Registry check failed for {package} on {registry}: {e}")
            # On error, assume it exists (fail safe — don't report false positives)
            return True

        return True
