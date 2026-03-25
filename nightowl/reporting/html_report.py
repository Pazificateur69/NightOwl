"""HTML report generator with Chart.js."""


def generate_html_report(context: dict) -> str:
    findings = context.get("findings", [])
    stats = context.get("severity_counts", {})
    title = context.get("title", "NightOwl Pentest Report")
    scan_id = context.get("scan_id", "N/A")
    timestamp = context.get("timestamp", "N/A")

    findings_rows = ""
    for f in findings:
        sev = f.get("severity", "info")
        color = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"
        }.get(sev, "#6b7280")
        findings_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
            <td>{f.get('title', '')}</td>
            <td>{f.get('target', '')}</td>
            <td>{f.get('cvss_score', 0)}</td>
            <td>{f.get('module_name', '')}</td>
        </tr>"""

    detail_sections = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        detail_sections += f"""
        <div class="finding-detail" id="finding-{i}">
            <h3>{i}. {f.get('title', '')}</h3>
            <p><strong>Severity:</strong> {sev.upper()} | <strong>CVSS:</strong> {f.get('cvss_score', 0)} | <strong>Module:</strong> {f.get('module_name', '')}</p>
            <p><strong>Target:</strong> {f.get('target', '')}</p>
            <h4>Evidence</h4><pre>{f.get('evidence', 'N/A')}</pre>
            <h4>Remediation</h4><p>{f.get('remediation', 'N/A')}</p>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
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
    .chart-container {{ background: #1e293b; border-radius: 8px; padding: 2rem; margin-bottom: 2rem; border: 1px solid #334155; max-width: 400px; margin-left: auto; margin-right: auto; }}
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
        <canvas id="sevChart"></canvas>
    </div>

    <h2 style="margin-bottom:1rem; color:#38bdf8;">Findings Summary</h2>
    <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>CVSS</th><th>Module</th></tr></thead>
        <tbody>{findings_rows}</tbody>
    </table>

    <h2 style="margin-bottom:1rem; color:#38bdf8;">Detailed Findings</h2>
    {detail_sections}

    <footer style="text-align:center; color:#475569; margin-top:3rem; padding:2rem;">
        Generated by NightOwl v1.0.0
    </footer>
</div>

<script>
new Chart(document.getElementById('sevChart'), {{
    type: 'doughnut',
    data: {{
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{{ data: [{stats.get('critical',0)}, {stats.get('high',0)}, {stats.get('medium',0)}, {stats.get('low',0)}, {stats.get('info',0)}],
            backgroundColor: ['#dc2626','#ea580c','#ca8a04','#2563eb','#6b7280'] }}]
    }},
    options: {{ responsive: true, plugins: {{ legend: {{ labels: {{ color: '#e2e8f0' }} }} }} }}
}});
</script>
</body></html>"""
