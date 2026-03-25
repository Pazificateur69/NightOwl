"""Rich formatters for CLI output."""

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.tree import Tree

from nightowl.models.finding import Finding, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

BANNER = r"""
[bold cyan]
    _   _ _       _     _    ___           _
   | \ | (_) __ _| |__ | |_ / _ \__      _| |
   |  \| | |/ _` | '_ \| __| | | \ \ /\ / / |
   | |\  | | (_| | | | | |_| |_| |\ V  V /| |
   |_| \_|_|\__, |_| |_|\__|\___/  \_/\_/ |_|
            |___/
[/bold cyan]
[dim]Advanced Penetration Testing Framework v1.0.0[/dim]
"""


def print_banner():
    console.print(BANNER)


def print_findings_table(findings: list[Finding]):
    table = Table(title="Findings", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Title", min_width=30)
    table.add_column("Target", width=20)
    table.add_column("CVSS", width=6)
    table.add_column("Module", width=18)

    for i, f in enumerate(findings, 1):
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            str(i),
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.title,
            f.target,
            f"{f.cvss_score:.1f}",
            f.module_name,
        )

    console.print(table)


def print_finding_detail(finding: Finding):
    color = SEVERITY_COLORS.get(finding.severity, "white")
    panel = Panel(
        f"[bold]{finding.title}[/bold]\n\n"
        f"[{color}]Severity: {finding.severity.value.upper()}[/{color}] | "
        f"CVSS: {finding.cvss_score}\n"
        f"Target: {finding.target}\n"
        f"Module: {finding.module_name}\n\n"
        f"[bold]Description:[/bold]\n{finding.description}\n\n"
        f"[bold]Evidence:[/bold]\n{finding.evidence}\n\n"
        f"[bold]Remediation:[/bold]\n{finding.remediation}",
        title=f"Finding: {finding.id[:8]}",
        border_style=color,
    )
    console.print(panel)


def print_scan_summary(stats: dict):
    tree = Tree("[bold]Scan Summary[/bold]")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = stats.get(sev, 0)
        if count > 0:
            color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}[sev]
            tree.add(f"[{color}]{sev.upper()}: {count}[/{color}]")
    console.print(tree)


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


def print_success(msg: str):
    console.print(f"[green][+][/green] {msg}")


def print_error(msg: str):
    console.print(f"[red][-][/red] {msg}")


def print_warning(msg: str):
    console.print(f"[yellow][!][/yellow] {msg}")


def print_info(msg: str):
    console.print(f"[blue][*][/blue] {msg}")
