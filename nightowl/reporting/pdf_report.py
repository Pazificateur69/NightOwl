"""PDF report generator via WeasyPrint."""

import logging

logger = logging.getLogger("nightowl")

try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


def generate_pdf_report(context: dict) -> bytes:
    """Generate PDF report. Falls back to HTML-to-bytes if WeasyPrint unavailable."""
    from nightowl.reporting.html_report import generate_html_report

    html_content = generate_html_report(context)

    if HAS_WEASYPRINT:
        try:
            doc = HTML(string=html_content)
            return doc.write_pdf()
        except Exception as e:
            logger.warning(f"WeasyPrint failed: {e}. Install system deps: apt install libpango-1.0-0 libgdk-pixbuf2.0-0")

    # Fallback: return HTML as bytes
    logger.info("WeasyPrint not available, saving as HTML")
    return html_content.encode("utf-8")
