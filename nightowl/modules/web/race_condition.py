"""Race condition / TOCTOU vulnerability detector."""

import asyncio
import logging
import time

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class RaceConditionPlugin(ScannerPlugin):
    name = "race-condition"
    description = "Detect race conditions via concurrent request analysis"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"
        concurrency = self.config.get("race_concurrency", 20)

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
                # Phase 1: Detect if endpoint is vulnerable to parallel request anomalies
                baseline = await client.get(url)

                # Send N concurrent identical requests
                async def send_request():
                    start = time.monotonic()
                    try:
                        resp = await client.get(url)
                        elapsed = time.monotonic() - start
                        return {"status": resp.status_code, "size": len(resp.content), "time": elapsed}
                    except (OSError, RuntimeError, ValueError, Exception) as exc:
                        logger.debug(f"Error: {exc}")
                        return None

                tasks = [send_request() for _ in range(concurrency)]
                results = await asyncio.gather(*tasks)
                results = [r for r in results if r]

                if not results:
                    return findings

                # Analyze for anomalies
                statuses = set(r["status"] for r in results)
                sizes = [r["size"] for r in results]
                times = [r["time"] for r in results]

                # Different status codes = possible race
                if len(statuses) > 1:
                    findings.append(Finding(
                        title=f"Race condition: inconsistent responses ({statuses})",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description=f"Concurrent requests to same endpoint returned different status codes: {statuses}",
                        evidence=f"URL: {url}\nConcurrency: {concurrency}\nStatuses: {statuses}\nResponse sizes: min={min(sizes)}, max={max(sizes)}",
                        remediation="Implement proper locking mechanisms. Use database transactions. Add idempotency keys.",
                        category="race-condition",
                    ))

                # Wildly different response sizes = different content served
                if max(sizes) - min(sizes) > 500 and len(set(sizes)) > 3:
                    findings.append(Finding(
                        title="Race condition: variable response sizes",
                        severity=Severity.MEDIUM,
                        description=f"Response sizes vary significantly under concurrent load",
                        evidence=f"URL: {url}\nMin size: {min(sizes)}\nMax size: {max(sizes)}\nUnique sizes: {len(set(sizes))}",
                        category="race-condition",
                    ))

                # Check for rate limiting gaps (all requests succeed = no rate limit)
                success_rate = sum(1 for r in results if r["status"] == 200) / len(results)
                if success_rate == 1.0 and concurrency >= 15:
                    findings.append(Finding(
                        title=f"No rate limiting detected ({concurrency} concurrent requests)",
                        severity=Severity.MEDIUM,
                        cvss_score=4.3,
                        description=f"All {concurrency} concurrent requests succeeded without rate limiting",
                        evidence=f"URL: {url}\nConcurrent requests: {concurrency}\nAll returned 200 OK\nAvg time: {sum(times)/len(times):.3f}s",
                        remediation="Implement rate limiting. Use token bucket or sliding window algorithms.",
                        category="race-condition",
                    ))

        except Exception as e:
            logger.warning(f"Race condition scan failed: {e}")

        return findings
