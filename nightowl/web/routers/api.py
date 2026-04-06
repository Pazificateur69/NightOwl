"""REST API endpoints for the NightOwl dashboard."""

import copy
import ipaddress
import logging
import re
import time
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, field_validator

from nightowl.config.scope import ScopeManager
from nightowl.core.engine import NightOwlEngine
from nightowl.db.database import Database
from nightowl.models.scan import ScanMode
from nightowl.models.target import Target
from nightowl.reporting.generator import ReportGenerator

logger = logging.getLogger("nightowl")

router = APIRouter()

# Simple in-memory rate limiting for scan creation
_scan_timestamps: list[float] = []
_MAX_SCANS_PER_MINUTE = 10

_VALID_HOST_RE = re.compile(
    r"^(?:https?://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?::\d+)?(?:/.*)?$"
)


def _is_valid_target(host: str) -> bool:
    """Validate that a target string is a plausible IP, domain, CIDR, or URL."""
    host = host.strip()
    if not host:
        return False
    # URL
    if host.startswith(("http://", "https://")):
        parsed = urlparse(host)
        return bool(parsed.hostname)
    # CIDR
    if "/" in host:
        try:
            ipaddress.ip_network(host, strict=False)
            return True
        except ValueError:
            return False
    # IP
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Domain
    return bool(_VALID_HOST_RE.match(host))


class ScanRequest(BaseModel):
    targets: list[str]
    mode: ScanMode = ScanMode.AUTO
    modules: list[str] | None = None

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v):
        if not v:
            raise ValueError("At least one target is required")
        if len(v) > 100:
            raise ValueError("Maximum 100 targets per scan")
        for t in v:
            if not _is_valid_target(t):
                raise ValueError(f"Invalid target format: {t!r}")
        return v


class TargetRequest(BaseModel):
    host: str


def _get_config(request: Request):
    """Get config from app state — injected at startup."""
    return request.app.state.config


async def _get_db(request: Request) -> Database:
    config = _get_config(request)
    db = Database(config.db_path)
    await db.init()
    return db


async def _run_scan_background(
    config, session_id: str, targets, mode: str, modules
):
    """Run scan in background — does not block the HTTP request.

    Uses a deep-copied config to avoid mutating shared application state.
    The pre-created session_id is reused so the DB row the client is polling
    gets updated in place.
    """
    scan_config = copy.deepcopy(config)

    engine = NightOwlEngine(scan_config)
    await engine.initialize()
    await engine.run_scan(targets, mode=mode, modules=modules, session_id=session_id)


@router.get("/scans")
async def list_scans(request: Request):
    db = await _get_db(request)
    return await db.get_scans()


@router.post("/scans")
async def create_scan(req: ScanRequest, request: Request, background_tasks: BackgroundTasks):
    # Rate limit: max N scans per minute
    now = time.monotonic()
    _scan_timestamps[:] = [ts for ts in _scan_timestamps if now - ts < 60]
    if len(_scan_timestamps) >= _MAX_SCANS_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {_MAX_SCANS_PER_MINUTE} scans per minute",
        )
    _scan_timestamps.append(now)

    config = _get_config(request)
    targets = [Target(host=h) for h in req.targets]
    scope = ScopeManager(config.scope)
    out_of_scope = [t.host for t in targets if not scope.is_target_allowed(t)]
    if out_of_scope:
        raise HTTPException(
            status_code=403,
            detail=(
                "One or more targets are outside the configured scope: "
                + ", ".join(out_of_scope)
            ),
        )

    # Create session entry immediately so the client gets an ID to poll
    from nightowl.models.scan import ScanSession
    session = ScanSession(
        name="api-scan",
        targets=targets,
        mode=req.mode,
        modules_enabled=req.modules or [],
    )
    session.start()

    db = await _get_db(request)
    await db.save_scan(session, [])

    # Run the actual scan in background, reusing the same session ID
    background_tasks.add_task(
        _run_scan_background, config, session.id, targets, req.mode, req.modules
    )

    return {
        "id": session.id,
        "status": "running",
        "message": "Scan started in background. Poll GET /api/scans/{id} for status.",
    }


def _validate_scan_id(scan_id: str) -> str:
    """Sanitize scan_id to prevent injection/traversal."""
    clean = re.sub(r"[^a-zA-Z0-9\-]", "", scan_id)
    if not clean or clean != scan_id:
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    return clean


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    scan_id = _validate_scan_id(scan_id)
    db = await _get_db(request)
    scans = await db.get_scans()
    scan = next((s for s in scans if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/findings")
async def get_findings(scan_id: str, request: Request):
    scan_id = _validate_scan_id(scan_id)
    db = await _get_db(request)
    return await db.get_findings(scan_id)


@router.get("/scans/{scan_id}/stats")
async def get_stats(scan_id: str, request: Request):
    scan_id = _validate_scan_id(scan_id)
    db = await _get_db(request)
    return await db.get_finding_stats(scan_id)


@router.get("/scans/{scan_id}/errors")
async def get_errors(scan_id: str, request: Request):
    scan_id = _validate_scan_id(scan_id)
    db = await _get_db(request)
    return await db.get_scan_errors(scan_id)


@router.get("/reports/{scan_id}")
async def generate_report(scan_id: str, request: Request, fmt: str = "html"):
    scan_id = _validate_scan_id(scan_id)
    config = _get_config(request)
    db = await _get_db(request)
    findings = await db.get_findings(scan_id)
    stats = await db.get_finding_stats(scan_id)

    gen = ReportGenerator(output_dir=config.output_dir)
    try:
        path = gen.generate(scan_id, findings, stats, fmt=fmt)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"path": path}


@router.get("/stats")
async def global_stats(request: Request):
    db = await _get_db(request)
    scans = await db.get_scans()
    return {
        "total_scans": len(scans),
        "completed": len([s for s in scans if s["status"] == "completed"]),
        "total_findings": sum(s.get("findings_count", 0) for s in scans),
    }
