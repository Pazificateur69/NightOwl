"""Web spider/crawler plugin."""

import logging
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class WebSpiderPlugin(ScannerPlugin):
    name = "web-spider"
    description = "Crawl web pages and discover links, forms, and parameters"
    version = "1.0.0"
    stage = "recon"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = target.url or f"https://{target.host}"
        max_depth = self.config.get("max_depth", 3)
        max_pages = self.config.get("max_pages", 100)

        visited = set()
        to_visit = [(base_url, 0)]
        discovered_urls = set()
        discovered_forms = []
        base_domain = urlparse(base_url).netloc

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                while to_visit and len(visited) < max_pages:
                    url, depth = to_visit.pop(0)
                    if url in visited or depth > max_depth:
                        continue
                    visited.add(url)

                    try:
                        resp = await client.get(url)
                        if "text/html" not in resp.headers.get("content-type", ""):
                            continue

                        soup = BeautifulSoup(resp.text, "html.parser")

                        # Extract links
                        for a in soup.find_all("a", href=True):
                            link = urljoin(url, a["href"])
                            parsed = urlparse(link)
                            if parsed.netloc == base_domain and link not in visited:
                                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                discovered_urls.add(clean)
                                to_visit.append((clean, depth + 1))

                        # Extract forms
                        for form in soup.find_all("form"):
                            action = urljoin(url, form.get("action", ""))
                            method = form.get("method", "GET").upper()
                            inputs = []
                            for inp in form.find_all(["input", "textarea", "select"]):
                                name = inp.get("name", "")
                                if name:
                                    inputs.append({"name": name, "type": inp.get("type", "text")})
                            if inputs:
                                discovered_forms.append({
                                    "action": action, "method": method,
                                    "inputs": inputs, "page": url,
                                })

                    except Exception as e:
                        logger.debug(f"Spider error on {url}: {e}")

        except Exception as e:
            logger.warning(f"Spider failed: {e}")

        if discovered_urls:
            url_list = "\n".join(sorted(discovered_urls)[:50])
            findings.append(Finding(
                title=f"Discovered {len(discovered_urls)} URLs on {base_domain}",
                severity=Severity.INFO,
                description=f"Web spider discovered {len(discovered_urls)} unique URLs",
                evidence=url_list,
                category="recon",
                metadata={"urls": list(discovered_urls)},
            ))

        for form in discovered_forms[:20]:
            params = ", ".join(i["name"] for i in form["inputs"])
            findings.append(Finding(
                title=f"Form found: {form['method']} {form['action']}",
                severity=Severity.INFO,
                description=f"Form with parameters: {params}",
                evidence=f"Page: {form['page']}\nAction: {form['action']}\nMethod: {form['method']}\nInputs: {params}",
                category="recon",
                metadata={"form": form},
            ))

        return findings
