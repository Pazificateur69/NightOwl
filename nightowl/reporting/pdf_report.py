"""PDF report generator via WeasyPrint."""

import logging

logger = logging.getLogger("nightowl")

try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


def generate_pdf_report(context: dict) -> bytes:
    """Generate PDF report. Raises if WeasyPrint is not available."""
    from nightowl.reporting.html_report import generate_html_report

    html_content = generate_html_report(context)

    if not HAS_WEASYPRINT:
        raise RuntimeError(
            "WeasyPrint is required for PDF generation. "
            "Install it with: pip install weasyprint"
        )

    try:
        doc = HTML(string=html_content)
        return doc.write_pdf()
    except Exception as e:
        raise RuntimeError(
            f"PDF generation failed: {e}. "
            "Ensure system deps are installed: apt install libpango-1.0-0 libgdk-pixbuf2.0-0"
        ) from e
