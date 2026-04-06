"""Multi-stage scan pipeline with confirmation gates."""

import asyncio
import logging
from enum import Enum

from nightowl.core.events import Event, EventBus
from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding
from nightowl.models.scan import ScanMode
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class Stage(str, Enum):
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post"
    REPORT = "report"


STAGE_ORDER = [Stage.RECON, Stage.SCAN, Stage.EXPLOIT, Stage.POST_EXPLOIT, Stage.REPORT]


class StageGate:
    """Confirmation gate for semi-auto mode."""

    def __init__(self, confirm_callback=None):
        self._confirm = confirm_callback
        self._event = asyncio.Event()
        self._approved = False

    async def request_confirmation(self, stage: Stage, findings: list[Finding]) -> bool:
        if self._confirm:
            self._approved = await self._confirm(stage, findings)
            return self._approved
        self._approved = True
        return True


class ScanPipeline:
    """Orchestrates the multi-stage scanning pipeline."""

    def __init__(
        self,
        plugins: dict[str, type[ScannerPlugin]],
        mode: ScanMode = ScanMode.SEMI,
        config: dict | None = None,
        plugin_configs: dict[str, dict] | None = None,
        confirm_callback=None,
    ):
        self.plugins = plugins
        self.mode = mode
        self.config = config or {}
        self.plugin_configs = plugin_configs or {}
        self.gate = StageGate(confirm_callback)
        self.event_bus = EventBus()
        self.current_stage: Stage | None = None
        self.all_findings: list[Finding] = []
        self.stage_results: dict[str, list[Finding]] = {}
        self.errors: list[dict] = []
        self._cancelled = False

    async def execute(self, targets: list[Target], stages: list[Stage] | None = None) -> list[Finding]:
        stages = stages or STAGE_ORDER
        self.all_findings = []

        for stage in stages:
            if self._cancelled:
                break

            # In semi-auto mode, confirm before exploit stages
            if self.mode == ScanMode.SEMI and stage in (Stage.EXPLOIT, Stage.POST_EXPLOIT):
                approved = await self.gate.request_confirmation(stage, self.all_findings)
                if not approved:
                    logger.info(f"Stage {stage.value} skipped by user")
                    continue

            # In manual mode, confirm every stage
            if self.mode == ScanMode.MANUAL:
                approved = await self.gate.request_confirmation(stage, self.all_findings)
                if not approved:
                    logger.info(f"Stage {stage.value} skipped by user")
                    continue

            await self._execute_stage(stage, targets)

        return self.all_findings

    async def _execute_stage(self, stage: Stage, targets: list[Target]) -> None:
        self.current_stage = stage
        stage_findings: list[Finding] = []

        await self.event_bus.emit(Event.STAGE_CHANGED, {"stage": stage.value})
        logger.info(f"--- Stage: {stage.value.upper()} ---")

        stage_plugins = [p for p in self.plugins.values() if p.stage == stage.value]
        if not stage_plugins:
            logger.info(f"No plugins for stage {stage.value}")
            return

        for plugin_cls in stage_plugins:
            if self._cancelled:
                break

            plugin = plugin_cls(
                config=self.plugin_configs.get(plugin_cls.name, self.config)
            )
            await self.event_bus.emit(Event.MODULE_STARTED, {"module": plugin.name})

            module_findings: list[Finding] = []
            for target in targets:
                try:
                    findings = await plugin.execute(
                        target, findings=self.all_findings
                    )
                    module_findings.extend(findings)
                    stage_findings.extend(findings)
                    for f in findings:
                        await self.event_bus.emit(Event.FINDING_DISCOVERED, {"finding": f})
                except Exception as e:
                    self.errors.append({
                        "module": plugin.name, "target": target.host,
                        "error": str(e), "stage": stage.value,
                    })
                    logger.error(f"[{plugin.name}] FAILED on {target.host}: {e}")
                    await self.event_bus.emit(Event.MODULE_FAILED, {
                        "module": plugin.name, "error": str(e)
                    })

            # Extend all_findings immediately so subsequent plugins in the
            # same stage can see findings from earlier plugins.
            self.all_findings.extend(module_findings)

            await self.event_bus.emit(Event.MODULE_COMPLETED, {
                "module": plugin.name, "findings_count": len(module_findings)
            })

        self.stage_results[stage.value] = stage_findings
        stage_errors = [e for e in self.errors if e["stage"] == stage.value]
        logger.info(f"Stage {stage.value}: {len(stage_findings)} findings, {len(stage_errors)} errors")

        # Surface module failures so they're visible in logs and reports
        if stage_errors:
            for err in stage_errors:
                logger.warning(
                    f"  [FAILED] {err['module']} on {err['target']}: {err['error']}"
                )

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def module_status(self) -> list[dict]:
        """Return per-module success/failure status for CLI reporting."""
        completed_modules = set()
        failed_modules = {}
        for err in self.errors:
            failed_modules[err["module"]] = err["error"]

        for stage_findings in self.stage_results.values():
            for f in stage_findings:
                if f.module_name:
                    completed_modules.add(f.module_name)

        statuses = []
        for name in self.plugins:
            if name in failed_modules:
                statuses.append({"module": name, "status": "failed", "error": failed_modules[name]})
            elif name in completed_modules:
                statuses.append({"module": name, "status": "completed"})
            else:
                statuses.append({"module": name, "status": "completed", "note": "no findings"})
        return statuses

    @property
    def progress(self) -> dict:
        completed = sum(1 for s in STAGE_ORDER if s.value in self.stage_results)
        total = len(STAGE_ORDER)
        return {
            "current_stage": self.current_stage.value if self.current_stage else None,
            "completed_stages": completed,
            "total_stages": total,
            "progress_pct": int(completed / total * 100) if total else 0,
            "total_findings": len(self.all_findings),
        }
