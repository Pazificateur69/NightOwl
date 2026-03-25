"""Web technology detection plugin."""

import logging
import re

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "Drupal": [r"sites/default/files", r'Drupal\.settings', r"drupal\.js"],
    "Joomla": [r"/media/jui/", r"com_content", r"/administrator/"],
    "React": [r"react\.production\.min\.js", r"_reactRootContainer", r"__NEXT_DATA__"],
    "Vue.js": [r"vue\.min\.js", r"vue\.runtime", r"v-cloak"],
    "Angular": [r"ng-version", r"angular\.min\.js", r"ng-app"],
    "jQuery": [r"jquery[\.-][\d\.]+\.min\.js", r"jquery\.min\.js"],
    "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.min\.js", r"bootstrap\.bundle"],
    "Tailwind CSS": [r"tailwindcss", r"tailwind\.min\.css"],
    "Next.js": [r"__NEXT_DATA__", r"/_next/static"],
    "Nuxt.js": [r"__NUXT__", r"/_nuxt/"],
    "Laravel": [r"laravel_session", r"csrf-token"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Express": [],
    "Flask": [],
    "PHP": [r"\.php", r"PHPSESSID"],
}

HEADER_TECHS = {
    "Server": None,
    "X-Powered-By": None,
    "X-Generator": None,
    "X-Drupal-Cache": "Drupal",
    "X-Pingback": "WordPress",
    "X-AspNet-Version": "ASP.NET",
    "X-AspNetMvc-Version": "ASP.NET MVC",
}


class TechDetectPlugin(ScannerPlugin):
    name = "tech-detect"
    description = "Detect web technologies, CMS, and frameworks"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
                resp = await client.get(url)

            detected = set()

            # Header analysis
            for header, tech in HEADER_TECHS.items():
                val = resp.headers.get(header)
                if val:
                    name = tech or f"{header}: {val}"
                    detected.add(name)

            # Cookie analysis
            cookies_str = str(resp.headers.get("set-cookie", ""))
            if "PHPSESSID" in cookies_str:
                detected.add("PHP")
            if "laravel_session" in cookies_str:
                detected.add("Laravel")
            if "JSESSIONID" in cookies_str:
                detected.add("Java")
            if "ASP.NET_SessionId" in cookies_str:
                detected.add("ASP.NET")

            # HTML body analysis
            body = resp.text
            for tech, patterns in TECH_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        detected.add(tech)
                        break

            # Meta generator
            gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
            if gen_match:
                detected.add(f"Generator: {gen_match.group(1)}")

            for tech in sorted(detected):
                findings.append(Finding(
                    title=f"Technology detected: {tech}",
                    severity=Severity.INFO,
                    description=f"Detected {tech} on {url}",
                    evidence=tech,
                    category="tech-detection",
                ))

        except Exception as e:
            logger.warning(f"Tech detection failed for {url}: {e}")

        return findings
