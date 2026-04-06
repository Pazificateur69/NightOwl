"""HTML report generator — fully self-contained (no external CDN)."""

import math
from html import escape


def _esc(val) -> str:
    """Escape HTML to prevent XSS in reports."""
    return escape(str(val)) if val else ""


def _svg_donut(stats: dict) -> str:
    """Generate a self-contained SVG doughnut chart from severity stats."""
    colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }
    labels = ["critical", "high", "medium", "low", "info"]
    values = [stats.get(k, 0) for k in labels]
    total = sum(values)

    if total == 0:
        return '<svg viewBox="0 0 200 200" width="200" height="200"><circle cx="100" cy="100" r="70" fill="none" stroke="#334155" stroke-width="30"/><text x="100" y="108" text-anchor="middle" fill="#94a3b8" font-size="14">No data</text></svg>'

    # Build SVG arcs
    arcs = ""
    offset = 0
    circumference = 2 * math.pi * 70
    for label, value in zip(labels, values):
        if value == 0:
            continue
        pct = value / total
        dash = pct * circumference
        gap = circumference - dash
        arcs += (
            f'<circle cx="100" cy="100" r="70" fill="none" '
            f'stroke="{colors[label]}" stroke-width="30" '
            f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
            f'stroke-dashoffset="{-offset:.1f}" '
            f'transform="rotate(-90 100 100)"/>\n'
        )
        offset += dash

    # Legend
    legend = ""
    ly = 10
    for label, value in zip(labels, values):
        if value == 0:
            continue
        legend += (
            f'<rect x="220" y="{ly}" width="12" height="12" fill="{colors[label]}" rx="2"/>'
            f'<text x="238" y="{ly + 11}" fill="#e2e8f0" font-size="12">'
            f'{label.capitalize()}: {value}</text>\n'
        )
        ly += 22

    return (
        f'<svg viewBox="0 0 360 200" width="360" height="200" xmlns="http://www.w3.org/2000/svg">\n'
        f'{arcs}'
        f'<text x="100" y="105" text-anchor="middle" fill="#e2e8f0" font-size="22" font-weight="bold">{total}</text>\n'
        f'<text x="100" y="122" text-anchor="middle" fill="#94a3b8" font-size="11">findings</text>\n'
        f'{legend}'
        f'</svg>'
    )


def generate_html_report(context: dict) -> str:
    findings = context.get("findings", [])
    stats = context.get("severity_counts", {})
    title = _esc(context.get("title", "NightOwl Pentest Report"))
    scan_id = _esc(context.get("scan_id", "N/A"))
    timestamp = _esc(context.get("timestamp", "N/A"))
    benchmark_target = _esc(context.get("benchmark_target", ""))
    benchmark_profile = _esc(context.get("benchmark_profile_description", ""))
    benchmark_probe_urls = context.get("benchmark_probe_urls", [])
    benchmark_verdict_counts = context.get("benchmark_verdict_counts", {})
    benchmark_top_modules = context.get("benchmark_top_modules", [])
    benchmark_artifact_scope = _esc(context.get("benchmark_artifact_scope", "raw"))

    findings_rows = ""
    for f in findings:
        sev = f.get("severity", "info")
        state = f.get("finding_state", "info")
        confidence = f.get("confidence_score", 0.5)
        color = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"
        }.get(sev, "#6b7280")
        findings_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{_esc(sev.upper())}</span></td>
            <td>{_esc(f.get('title', ''))}</td>
            <td>{_esc(f.get('target', ''))}</td>
            <td>{_esc(state.upper())}</td>
            <td>{_esc(f"{float(confidence):.2f}")}</td>
            <td>{_esc(f.get('cvss_score', 0))}</td>
            <td>{_esc(f.get('module_name', ''))}</td>
        </tr>"""

    detail_sections = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        state = f.get("finding_state", "info")
        confidence = f.get("confidence_score", 0.5)
        maturity = f.get("metadata", {}).get("module_maturity", "experimental")
        detail_sections += f"""
        <div class="finding-detail" id="finding-{i}">
            <h3>{i}. {_esc(f.get('title', ''))}</h3>
            <p><strong>Severity:</strong> {_esc(sev.upper())} | <strong>State:</strong> {_esc(state.upper())} | <strong>Confidence:</strong> {_esc(f"{float(confidence):.2f}")} | <strong>CVSS:</strong> {_esc(f.get('cvss_score', 0))} | <strong>Module:</strong> {_esc(f.get('module_name', ''))}</p>
            <p><strong>Module maturity:</strong> {_esc(maturity)}</p>
            <p><strong>Target:</strong> {_esc(f.get('target', ''))}</p>
            <h4>Evidence</h4><pre>{_esc(f.get('evidence', 'N/A'))}</pre>
            <h4>Remediation</h4><p>{_esc(f.get('remediation', 'N/A'))}</p>
        </div>"""

    svg_chart = _svg_donut(stats)
    benchmark_section = ""
    if benchmark_target:
        verdict_cards = "".join(
            f"""
            <div class="mini-stat">
                <div class="mini-label">{_esc(name)}</div>
                <div class="mini-num">{_esc(value)}</div>
            </div>
            """
            for name, value in (
                ("confirmed_hit", benchmark_verdict_counts.get("confirmed_hit", 0)),
                ("expected_hit", benchmark_verdict_counts.get("expected_hit", 0)),
                ("quiet_expected", benchmark_verdict_counts.get("quiet_expected", 0)),
                ("quiet_violation", benchmark_verdict_counts.get("quiet_violation", 0)),
                ("missed_expected", benchmark_verdict_counts.get("missed_expected", 0)),
                ("likely_false_positive", benchmark_verdict_counts.get("likely_false_positive", 0)),
                ("inconclusive", benchmark_verdict_counts.get("inconclusive", 0)),
            )
        )
        top_modules = "".join(
            f'<li><code>{_esc(item["name"])}</code>: {_esc(item["count"])}</li>'
            for item in benchmark_top_modules
        )
        probe_list = "".join(f"<li><code>{_esc(probe)}</code></li>" for probe in benchmark_probe_urls)
        benchmark_section = f"""
        <section class="benchmark-panel">
            <h2>Benchmark Context</h2>
            <p><strong>Target:</strong> {benchmark_target}</p>
            <p><strong>Profile:</strong> {benchmark_profile}</p>
            <p><strong>Artifact Scope:</strong> {benchmark_artifact_scope}</p>
            <div class="mini-stats">{verdict_cards}</div>
            {'<h3>Strongest Module Signal</h3><ul>' + top_modules + '</ul>' if top_modules else ''}
            {'<h3>Probe URLs</h3><ul>' + probe_list + '</ul>' if probe_list else ''}
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
    header {{ background: linear-gradient(135deg, #1e293b, #0f172a); padding: 2rem; border-radius: 12px; margin-bottom: 2rem; border: 1px solid #334155; }}
    header h1 {{ font-size: 2rem; color: #38bdf8; }}
    header p {{ color: #94a3b8; }}
    .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }}
    .stat {{ background: #1e293b; padding: 1.5rem; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
    .stat .num {{ font-size: 2rem; font-weight: bold; }}
    .stat .label {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }}
    .chart-container {{ background: #1e293b; border-radius: 8px; padding: 2rem; margin-bottom: 2rem; border: 1px solid #334155; display: flex; justify-content: center; }}
    .benchmark-panel {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; border: 1px solid #334155; }}
    .benchmark-panel h2 {{ color: #38bdf8; margin-bottom: 0.75rem; }}
    .benchmark-panel h3 {{ color: #94a3b8; margin: 1rem 0 0.5rem; font-size: 1rem; }}
    .mini-stats {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 0.75rem; margin: 1rem 0; }}
    .mini-stat {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 0.75rem; }}
    .mini-label {{ color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; }}
    .mini-num {{ color: #e2e8f0; font-size: 1.5rem; font-weight: bold; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 2rem; }}
    th {{ background: #334155; padding: 12px; text-align: left; font-size: 0.85rem; text-transform: uppercase; color: #94a3b8; }}
    td {{ padding: 12px; border-bottom: 1px solid #1e293b; }}
    tr:hover {{ background: #334155; }}
    .badge {{ padding: 4px 10px; border-radius: 4px; color: white; font-size: 0.75rem; font-weight: bold; }}
    .finding-detail {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border: 1px solid #334155; }}
    .finding-detail h3 {{ color: #38bdf8; margin-bottom: 0.5rem; }}
    .finding-detail h4 {{ color: #94a3b8; margin-top: 1rem; margin-bottom: 0.5rem; }}
    pre {{ background: #0f172a; padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }}
    .owl-logo {{ font-size: 2.5rem; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <span class="owl-logo">&#x1F989;</span>
        <h1>{title}</h1>
        <p>Scan ID: {scan_id} | Generated: {timestamp}</p>
    </header>

    <div class="stats">
        <div class="stat"><div class="num" style="color:#dc2626">{stats.get('critical', 0)}</div><div class="label">Critical</div></div>
        <div class="stat"><div class="num" style="color:#ea580c">{stats.get('high', 0)}</div><div class="label">High</div></div>
        <div class="stat"><div class="num" style="color:#ca8a04">{stats.get('medium', 0)}</div><div class="label">Medium</div></div>
        <div class="stat"><div class="num" style="color:#2563eb">{stats.get('low', 0)}</div><div class="label">Low</div></div>
        <div class="stat"><div class="num" style="color:#6b7280">{stats.get('info', 0)}</div><div class="label">Info</div></div>
    </div>

    <div class="chart-container">
        {svg_chart}
    </div>

    {benchmark_section}

    <h2 style="margin-bottom:1rem; color:#38bdf8;">Findings Summary</h2>
    <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>State</th><th>Confidence</th><th>CVSS</th><th>Module</th></tr></thead>
        <tbody>{findings_rows}</tbody>
    </table>

    <h2 style="margin-bottom:1rem; color:#38bdf8;">Detailed Findings</h2>
    {detail_sections}

    <footer style="text-align:center; color:#475569; margin-top:3rem; padding:2rem;">
        Generated by NightOwl v1.0.0
    </footer>
</div>
</body></html>"""
