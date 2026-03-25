"""REST API endpoints for the NightOwl dashboard."""

import asyncio

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from nightowl.config.schema import load_config
from nightowl.core.engine import NightOwlEngine
from nightowl.db.database import Database
from nightowl.models.target import Target
from nightowl.reporting.generator import ReportGenerator

router = APIRouter()


class ScanRequest(BaseModel):
    targets: list[str]
    mode: str = "auto"
    modules: list[str] | None = None


class TargetRequest(BaseModel):
    host: str


@router.get("/scans")
async def list_scans():
    config = load_config("./configs/default.yaml")
    db = Database(config.db_path)
    await db.init()
    return await db.get_scans()


@router.post("/scans")
async def create_scan(req: ScanRequest):
    config = load_config("./configs/default.yaml")
    engine = NightOwlEngine(config)
    await engine.initialize()

    targets = [Target(host=h) for h in req.targets]
    session = await engine.run_scan(targets, mode=req.mode, modules=req.modules)
    return {"id": session.id, "status": session.status.value, "findings_count": session.findings_count}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    config = load_config("./configs/default.yaml")
    db = Database(config.db_path)
    await db.init()
    scans = await db.get_scans()
    scan = next((s for s in scans if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/findings")
async def get_findings(scan_id: str):
    config = load_config("./configs/default.yaml")
    db = Database(config.db_path)
    await db.init()
    return await db.get_findings(scan_id)


@router.get("/scans/{scan_id}/stats")
async def get_stats(scan_id: str):
    config = load_config("./configs/default.yaml")
    db = Database(config.db_path)
    await db.init()
    return await db.get_finding_stats(scan_id)


@router.get("/reports/{scan_id}")
async def generate_report(scan_id: str, fmt: str = "html"):
    config = load_config("./configs/default.yaml")
    db = Database(config.db_path)
    await db.init()
    findings = await db.get_findings(scan_id)
    stats = await db.get_finding_stats(scan_id)

    gen = ReportGenerator(output_dir=config.output_dir)
    path = gen.generate(scan_id, findings, stats, fmt=fmt)
    return {"path": path}


@router.get("/stats")
async def global_stats():
    config = load_config("./configs/default.yaml")
    db = Database(config.db_path)
    await db.init()
    scans = await db.get_scans()
    return {
        "total_scans": len(scans),
        "completed": len([s for s in scans if s["status"] == "completed"]),
        "total_findings": sum(s.get("findings_count", 0) for s in scans),
    }
