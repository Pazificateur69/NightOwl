"""NightOwl main orchestrator engine."""

import asyncio
import logging
from datetime import datetime, timezone

from nightowl.config.scope import ScopeManager
from nightowl.core.events import Event, EventBus
from nightowl.core.pipeline import ScanPipeline, Stage
from nightowl.core.plugin_loader import PluginLoader
from nightowl.db.database import Database
from nightowl.models.config import NightOwlConfig
from nightowl.models.scan import ScanMode, ScanResult, ScanSession, ScanStatus
from nightowl.models.target import Target
from nightowl.utils.logger import set_correlation_id

logger = logging.getLogger("nightowl")


class NightOwlEngine:
    """Central orchestrator for all scanning operations."""

    def __init__(self, config: NightOwlConfig):
        self.config = config
        self.plugin_loader = PluginLoader()
        self.event_bus = EventBus()
        self.db = Database(config.db_path)
        self.scope = ScopeManager(config.scope)
        self._sessions: dict[str, ScanSession] = {}

    def _build_plugin_configs(
        self, plugin_names: list[str]
    ) -> dict[str, dict]:
        """Merge global defaults with per-module options for pipeline execution."""
        base_config = self.config.model_dump()
        merged: dict[str, dict] = {}
        for name in plugin_names:
            plugin_config = dict(base_config)
            plugin_config.update(self.config.get_module_options(name))
            merged[name] = plugin_config
        return merged

    async def initialize(self) -> None:
        """Load plugins and initialize database."""
        self.plugin_loader.load_all()
        await self.db.init()
        logger.info(f"NightOwl initialized with {len(self.plugin_loader.all_plugins)} plugins")

    async def run_scan(
        self,
        targets: list[Target],
        mode: str = "semi",
        modules: list[str] | None = None,
        stages: list[Stage] | None = None,
        confirm_callback=None,
        session_id: str | None = None,
    ) -> ScanSession:
        """Execute a full scan against targets.

        If session_id is provided, the engine reuses that ID (useful when the
        API already created a placeholder row the client is polling).
        """
        # Enforce scope on all targets
        allowed_targets = []
        for t in targets:
            if self.scope.is_target_allowed(t):
                allowed_targets.append(t)
            else:
                logger.warning(f"Target '{t.host}' is outside scope — skipped")
        if not allowed_targets:
            raise ValueError("All targets are outside the configured scope. Define scope in config.")

        # Set correlation ID for structured log tracing
        scan_cid = set_correlation_id(session_id)

        session = ScanSession(
            name=f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            targets=allowed_targets,
            mode=ScanMode(mode),
            modules_enabled=modules or [],
        )
        # Reuse caller-provided ID so the DB row is updated in place
        if session_id:
            session.id = session_id

        self._sessions[session.id] = session

        # Filter plugins
        available = self.plugin_loader.all_plugins
        if modules is not None:
            plugins = {k: v for k, v in available.items() if k in modules}
        else:
            plugins = {
                k: v for k, v in available.items()
                if self.config.is_module_enabled(k)
            }

        plugin_configs = self._build_plugin_configs(list(plugins.keys()))

        pipeline = ScanPipeline(
            plugins=plugins,
            mode=session.mode,
            config=self.config.model_dump(),
            plugin_configs=plugin_configs,
            confirm_callback=confirm_callback,
        )

        session.start()
        await self.event_bus.emit(Event.SCAN_STARTED, {"session_id": session.id})

        try:
            findings = await pipeline.execute(allowed_targets, stages)
            session.complete(findings_count=len(findings))
            session.errors = pipeline.errors
            session.module_status = pipeline.module_status
            await self.event_bus.emit(Event.SCAN_COMPLETED, {
                "session_id": session.id,
                "findings_count": len(findings),
                "errors_count": len(pipeline.errors),
            })

            # Save to DB (upsert if session_id was reused, insert otherwise).
            # Also persist any module errors tracked by the pipeline.
            await self.db.save_scan(session, findings, errors=pipeline.errors)

            # Log module failures clearly so they're visible in CLI output
            if pipeline.errors:
                logger.warning(
                    f"Scan completed with {len(pipeline.errors)} module error(s):"
                )
                for err in pipeline.errors:
                    logger.warning(
                        f"  - {err['module']} on {err['target']}: {err['error']}"
                    )

        except Exception as e:
            session.fail()
            session.errors = pipeline.errors
            await self.event_bus.emit(Event.SCAN_FAILED, {
                "session_id": session.id,
                "error": str(e),
            })
            logger.error(f"Scan failed: {e}")
            await self.db.save_scan(session, pipeline.all_findings, errors=pipeline.errors)

        return session

    async def run_module(
        self, module_name: str, target: Target, **kwargs
    ) -> ScanResult:
        """Run a single module against a single target."""
        plugin_cls = self.plugin_loader.get_plugin(module_name)
        if not plugin_cls:
            return ScanResult(
                scan_id="", module_name=module_name,
                success=False, errors=[f"Module '{module_name}' not found"],
            )

        plugin = plugin_cls(config=self.config.get_module_options(module_name))

        import time
        start = time.time()
        try:
            findings = await plugin.execute(target, **kwargs)
            return ScanResult(
                scan_id="",
                module_name=module_name,
                findings=findings,
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return ScanResult(
                scan_id="",
                module_name=module_name,
                success=False,
                errors=[str(e)],
                duration_seconds=time.time() - start,
            )

    def list_plugins(self) -> list[dict]:
        return [
            {
                "name": p.name,
                "description": p.description,
                "stage": p.stage,
                "version": p.version,
            }
            for p in self.plugin_loader.all_plugins.values()
        ]

    def get_session(self, session_id: str) -> ScanSession | None:
        return self._sessions.get(session_id)

    async def shutdown(self) -> None:
        """Graceful shutdown: cancel running scans, close DB, flush events."""
        logger.info("NightOwl engine shutting down...")

        # Cancel any running pipelines
        for session_id, session in list(self._sessions.items()):
            if session.status.value in ("running", "pending"):
                logger.info(f"  Cancelling scan {session_id}")
                session.fail()

        # Close database connection
        if self.db and hasattr(self.db, "engine") and self.db.engine:
            try:
                self.db.engine.dispose()
                logger.debug("Database connections closed")
            except Exception as e:
                logger.warning(f"Error closing database: {e}")

        # Clear event bus
        self.event_bus.clear()

        # Reset global rate limiter
        from nightowl.utils.rate_limiter import reset_global_limiter
        reset_global_limiter()

        logger.info("NightOwl engine shutdown complete")
