"""NightOwl CLI - Main entry point."""

import asyncio
import signal
import sys

import click
from rich.prompt import Confirm
from rich.table import Table

from nightowl import __version__
from nightowl.cli.formatters import (
    console, create_progress, print_banner, print_error, print_findings_table,
    print_info, print_scan_summary, print_success, print_warning,
)
from nightowl.config.schema import load_config
from nightowl.core.engine import NightOwlEngine
from nightowl.core.pipeline import Stage
from nightowl.models.config import ModuleConfig
from nightowl.models.scan import ScanMode
from nightowl.models.target import Target

_engine_ref: NightOwlEngine | None = None


def _handle_shutdown(signum, frame):
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    print_warning("\nShutdown signal received, cleaning up...")
    if _engine_ref is not None:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_engine_ref.shutdown())
            else:
                asyncio.run(_engine_ref.shutdown())
        except RuntimeError:
            pass
    sys.exit(130)


def run_async(coro):
    """Run an async coroutine from sync context."""
    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)
    return asyncio.run(coro)


def _ensure_target_in_scope(config, target_host: str):
    """Require an explicit scope for CLI scans."""
    if (
        not config.scope.allowed_hosts
        and not config.scope.allowed_ips
        and not config.scope.allowed_networks
    ):
        raise click.ClickException(
            "No scope defined in config. Refusing to auto-authorize CLI targets. "
            "Define allowed_hosts/allowed_ips/allowed_networks explicitly."
        )


@click.group()
@click.version_option(version=__version__, prog_name="NightOwl")
@click.option("--config", "-c", default="./configs/default.yaml", help="Config file path")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.pass_context
def cli(ctx, config, verbose):
    """NightOwl - Advanced Penetration Testing Framework"""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["verbose"] = verbose


@cli.command()
@click.argument("target")
@click.option("--dns", is_flag=True, help="DNS enumeration")
@click.option("--ports", is_flag=True, help="Port scanning")
@click.option("--subdomains", is_flag=True, help="Subdomain discovery")
@click.option("--tech", is_flag=True, help="Technology detection")
@click.option("--full", is_flag=True, help="Run all recon modules")
@click.pass_context
def recon(ctx, target, dns, ports, subdomains, tech, full):
    """Run reconnaissance against a target."""
    print_banner()
    config = load_config(ctx.obj["config_path"])
    engine = NightOwlEngine(config)

    modules = []
    if full or dns:
        modules.append("dns-enum")
    if full or subdomains:
        modules.append("subdomain-enum")
    if full or ports:
        modules.append("port-scanner")
    if full or tech:
        modules.append("tech-detect")
    if full:
        modules.extend(["service-fingerprint", "whois-lookup", "web-spider"])
    if not modules:
        modules = ["dns-enum", "port-scanner", "tech-detect"]

    _ensure_target_in_scope(config, target)
    print_info(f"Target: {target}")
    print_info(f"Modules: {', '.join(modules)}")

    t = Target(host=target)

    async def _run():
        await engine.initialize()
        session = await engine.run_scan([t], mode="auto", modules=modules, stages=[Stage.RECON])
        return session

    with create_progress() as progress:
        task = progress.add_task("Reconnaissance...", total=100)
        session = run_async(_run())
        progress.update(task, completed=100)

    if session.findings_count > 0:
        print_success(f"Found {session.findings_count} results")
    else:
        print_warning("No findings")


@cli.group()
def scan():
    """Run vulnerability scans."""
    pass


@scan.command("web")
@click.argument("target")
@click.option("--sqli", is_flag=True, help="SQL injection tests")
@click.option("--xss", is_flag=True, help="XSS tests")
@click.option("--core", "core_only", is_flag=True, help="Run the hardened core web modules")
@click.option("--all", "all_modules", is_flag=True, help="Run all web modules")
@click.pass_context
def scan_web(ctx, target, sqli, xss, core_only, all_modules):
    """Scan web application for vulnerabilities."""
    print_banner()
    config = load_config(ctx.obj["config_path"])
    engine = NightOwlEngine(config)

    if all_modules:
        from nightowl.modules import BUILTIN_MODULES
        modules = [
            name for name, path in BUILTIN_MODULES.items()
            if ".modules.web." in path
        ]
        # When running all web modules, let the pipeline execute all stages
        # so modules tagged as 'recon' or 'post' also get a chance to run.
        stages = None
    elif core_only:
        from nightowl.modules import get_core_modules
        modules = get_core_modules(".modules.web.")
        stages = [Stage.SCAN]
    else:
        modules = ["header-analyzer"]
        if sqli:
            modules.append("sqli-scanner")
        if xss:
            modules.append("xss-scanner")
        stages = [Stage.SCAN]

    _ensure_target_in_scope(config, target)
    print_info(f"Target: {target}")
    print_info(f"Modules: {', '.join(modules)}")

    t = Target(host=target)

    async def _run():
        await engine.initialize()
        return await engine.run_scan([t], mode="auto", modules=modules, stages=stages)

    session = run_async(_run())
    print_success(f"Scan complete: {session.findings_count} findings")


@scan.command("network")
@click.argument("target")
@click.option("--ports", default="1-1000", help="Port range")
@click.option("--vuln", is_flag=True, help="Vulnerability matching")
@click.pass_context
def scan_network(ctx, target, ports, vuln):
    """Scan network infrastructure."""
    print_banner()
    config = load_config(ctx.obj["config_path"])
    engine = NightOwlEngine(config)

    modules = ["deep-port-scan"]
    if vuln:
        modules.extend(["vuln-matcher", "smb-enum", "ssh-audit", "ftp-scanner"])

    _ensure_target_in_scope(config, target)

    # Pass port range via proper ModuleConfig so the plugin receives it
    config.modules.append(
        ModuleConfig(name="deep-port-scan", enabled=True, options={"port_range": ports})
    )

    print_info(f"Target: {target} | Ports: {ports}")
    t = Target(host=target)

    async def _run():
        await engine.initialize()
        return await engine.run_scan([t], mode="auto", modules=modules, stages=[Stage.SCAN])

    session = run_async(_run())
    print_success(f"Scan complete: {session.findings_count} findings")


@scan.command("ad")
@click.argument("target")
@click.option("--domain", required=True, help="AD domain name")
@click.option("--user", default=None, help="Username for authentication")
@click.option("--password", default=None, help="Password")
@click.pass_context
def scan_ad(ctx, target, domain, user, password):
    """Scan Active Directory environment."""
    print_banner()
    config = load_config(ctx.obj["config_path"])
    engine = NightOwlEngine(config)

    modules = ["ldap-enum", "kerberos-scanner", "ad-recon"]
    _ensure_target_in_scope(config, target)
    print_info(f"Target DC: {target} | Domain: {domain}")

    t = Target(host=target, credentials={"domain": domain, "user": user, "password": password})

    async def _run():
        await engine.initialize()
        return await engine.run_scan([t], mode="semi", modules=modules)

    session = run_async(_run())
    print_success(f"AD scan complete: {session.findings_count} findings")


@cli.command()
@click.argument("target")
@click.option("--auto", "auto_mode", is_flag=True, help="Full auto exploitation")
@click.option("--confirm", "semi_mode", is_flag=True, default=True, help="Confirm before exploiting")
@click.pass_context
def exploit(ctx, target, auto_mode, semi_mode):
    """Run exploitation modules."""
    print_banner()
    print_warning("Exploitation mode - ensure you have authorization!")

    if not auto_mode:
        if not Confirm.ask("Do you have written authorization to exploit this target?"):
            print_error("Exploitation cancelled. Get authorization first.")
            return

    config = load_config(ctx.obj["config_path"])
    engine = NightOwlEngine(config)
    mode = "auto" if auto_mode else "semi"

    _ensure_target_in_scope(config, target)
    t = Target(host=target)

    async def _confirm(stage, findings):
        return Confirm.ask(f"Proceed with {stage.value}? ({len(findings)} findings so far)")

    async def _run():
        await engine.initialize()
        return await engine.run_scan(
            [t], mode=mode, stages=[Stage.EXPLOIT],
            confirm_callback=_confirm if not auto_mode else None,
        )

    session = run_async(_run())
    print_success(f"Exploitation complete: {session.findings_count} findings")


@cli.command()
@click.argument("target")
@click.option("--mode", type=click.Choice(["auto", "semi", "manual"]), default="semi")
@click.option("--config", "config_path", default=None, help="Override config file")
@click.pass_context
def full(ctx, target, mode, config_path):
    """Run full pentest pipeline (recon -> scan -> exploit -> post -> report)."""
    print_banner()
    print_warning("Full pentest mode - all stages will be executed")

    config_file = config_path or ctx.obj["config_path"]
    config = load_config(config_file)
    engine = NightOwlEngine(config)

    _ensure_target_in_scope(config, target)
    t = Target(host=target)

    async def _confirm(stage, findings):
        return Confirm.ask(f"Proceed to {stage.value}? ({len(findings)} findings)")

    async def _run():
        await engine.initialize()
        return await engine.run_scan(
            [t], mode=mode,
            confirm_callback=_confirm if mode != "auto" else None,
        )

    session = run_async(_run())
    print_success(f"Full scan complete: {session.findings_count} findings")


@cli.command()
@click.argument("scan_id")
@click.option("--format", "fmt", type=click.Choice(["html", "pdf", "md"]), default="html")
@click.option("--output", "-o", default="./reports", help="Output directory")
@click.pass_context
def report(ctx, scan_id, fmt, output):
    """Generate a report from scan results."""
    print_banner()
    from nightowl.reporting.generator import ReportGenerator

    config = load_config(ctx.obj["config_path"])

    async def _run():
        db = __import__("nightowl.db.database", fromlist=["Database"]).Database(config.db_path)
        await db.init()
        findings = await db.get_findings(scan_id)
        stats = await db.get_finding_stats(scan_id)

        generator = ReportGenerator(output_dir=output)
        path = generator.generate(scan_id, findings, stats, fmt=fmt)
        return path

    path = run_async(_run())
    print_success(f"Report generated: {path}")


@cli.command()
@click.option("--port", "-p", default=8080, help="Dashboard port")
@click.option("--host", "-h", default="127.0.0.1", help="Dashboard host")
@click.pass_context
def dashboard(ctx, port, host):
    """Launch the web dashboard."""
    print_banner()
    print_info(f"Starting dashboard on http://{host}:{port}")

    import uvicorn
    from nightowl.web.app import create_app

    config = load_config(ctx.obj["config_path"])
    app = create_app(config)
    uvicorn.run(app, host=host, port=port, log_level="info")


@cli.command("plugins")
@click.option("--list", "list_plugins", is_flag=True, help="List all plugins")
@click.option(
    "--maturity",
    type=click.Choice(["recommended", "usable-with-caution", "experimental"]),
    default=None,
    help="Filter plugins by maturity",
)
@click.option("--core-only", is_flag=True, help="Show only the official core modules")
@click.pass_context
def plugins_cmd(ctx, list_plugins, maturity, core_only):
    """Manage plugins."""
    if list_plugins:
        from nightowl.core.plugin_loader import PluginLoader
        from nightowl.modules import get_module_maturity, is_core_module

        loader = PluginLoader()
        plugins = loader.load_all()

        table = Table(title="Available Plugins")
        table.add_column("Name", style="cyan")
        table.add_column("Stage")
        table.add_column("Maturity")
        table.add_column("Core")
        table.add_column("Description")

        for name, cls in sorted(plugins.items()):
            module_maturity = get_module_maturity(name)
            module_core = is_core_module(name)
            if maturity and module_maturity != maturity:
                continue
            if core_only and not module_core:
                continue
            table.add_row(
                name,
                cls.stage,
                module_maturity,
                "yes" if module_core else "no",
                cls.description,
            )

        console.print(table)


@cli.command()
@click.option("--init", "init_config", is_flag=True, help="Create default config")
@click.option("--validate", "validate_config", is_flag=True, help="Validate config")
@click.pass_context
def config(ctx, init_config, validate_config):
    """Manage configuration."""
    if init_config:
        import shutil
        from pathlib import Path

        src = Path(__file__).parent.parent.parent / "configs" / "default.yaml"
        dst = Path("./nightowl.yaml")
        if src.exists():
            shutil.copy(src, dst)
            print_success(f"Config created at {dst}")
        else:
            print_error("Default config template not found")

    if validate_config:
        from nightowl.config.schema import validate_config as _validate

        cfg = load_config(ctx.obj["config_path"])
        warnings = _validate(cfg)
        if warnings:
            for w in warnings:
                print_warning(w)
        else:
            print_success("Configuration is valid")


if __name__ == "__main__":
    cli()
