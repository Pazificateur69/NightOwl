"""Report generation engine."""

import logging
from datetime import datetime, timezone
from pathlib import Path

from nightowl.reporting.html_report import generate_html_report
from nightowl.reporting.markdown_report import generate_markdown_report
from nightowl.reporting.pdf_report import generate_pdf_report

logger = logging.getLogger("nightowl")


class ReportGenerator:
    """Generates pentest reports in multiple formats."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        scan_id: str,
        findings: list[dict],
        stats: dict,
        fmt: str = "html",
        title: str = "NightOwl Pentest Report",
        extra_context: dict | None = None,
        filename_suffix: str | None = None,
    ) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        short_id = scan_id[:8] if scan_id else "unknown"
        filename = f"nightowl-{short_id}-{timestamp}"
        if filename_suffix:
            filename = f"{filename}-{filename_suffix}"

        context = {
            "scan_id": scan_id,
            "title": title,
            "timestamp": timestamp,
            "findings": findings,
            "stats": stats,
            "total_findings": len(findings),
            "severity_counts": stats,
        }
        if extra_context:
            context.update(extra_context)

        if fmt == "html":
            path = self.output_dir / f"{filename}.html"
            content = generate_html_report(context)
        elif fmt == "pdf":
            path = self.output_dir / f"{filename}.pdf"
            content = generate_pdf_report(context)
            path.write_bytes(content)
            logger.info(f"PDF report generated: {path}")
            return str(path)
        elif fmt == "md":
            path = self.output_dir / f"{filename}.md"
            content = generate_markdown_report(context)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        path.write_text(content, encoding="utf-8")
        logger.info(f"Report generated: {path}")
        return str(path)
