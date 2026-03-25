"""NightOwl main orchestrator engine."""

import asyncio
import logging
from datetime import datetime, timezone

from nightowl.core.events import Event, EventBus
from nightowl.core.pipeline import ScanPipeline, Stage
from nightowl.core.plugin_loader import PluginLoader
from nightowl.db.database import Database
from nightowl.models.config import NightOwlConfig
from nightowl.models.scan import ScanMode, ScanResult, ScanSession, ScanStatus
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class NightOwlEngine:
    """Central orchestrator for all scanning operations."""

    def __init__(self, config: NightOwlConfig):
        self.config = config
        self.plugin_loader = PluginLoader()
        self.event_bus = EventBus()
        self.db = Database(config.db_path)
        self._sessions: dict[str, ScanSession] = {}

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
    ) -> ScanSession:
        """Execute a full scan against targets."""
        session = ScanSession(
            name=f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            targets=targets,
            mode=ScanMode(mode),
            modules_enabled=modules or [],
        )
        self._sessions[session.id] = session

        # Filter plugins
        available = self.plugin_loader.all_plugins
        if modules:
            plugins = {k: v for k, v in available.items() if k in modules}
        else:
            plugins = {
                k: v for k, v in available.items()
                if self.config.is_module_enabled(k)
            }

        pipeline = ScanPipeline(
            plugins=plugins,
            mode=session.mode,
            config=self.config.model_dump(),
            confirm_callback=confirm_callback,
        )

        session.start()
        await self.event_bus.emit(Event.SCAN_STARTED, {"session_id": session.id})

        try:
            findings = await pipeline.execute(targets, stages)
            session.complete(findings_count=len(findings))
            await self.event_bus.emit(Event.SCAN_COMPLETED, {
                "session_id": session.id,
                "findings_count": len(findings),
            })

            # Save to DB
            await self.db.save_scan(session, findings)

        except Exception as e:
            session.fail()
            await self.event_bus.emit(Event.SCAN_FAILED, {
                "session_id": session.id,
                "error": str(e),
            })
            logger.error(f"Scan failed: {e}")

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
        self.event_bus.clear()
        logger.info("NightOwl engine shutdown")
