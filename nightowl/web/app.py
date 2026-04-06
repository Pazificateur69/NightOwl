"""FastAPI web dashboard application."""

import logging
import os
import secrets
from collections import Counter
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from nightowl.models.config import NightOwlConfig
from nightowl.web.routers.api import router as api_router

logger = logging.getLogger("nightowl")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all HTTP responses."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


def _get_api_key() -> str | None:
    """Get the API key from environment or return None (no auth)."""
    return os.environ.get("NIGHTOWL_API_KEY")


async def verify_api_key(request: Request):
    """Dependency that checks API key when NIGHTOWL_API_KEY is set."""
    expected_key = _get_api_key()
    if not expected_key:
        return  # No auth configured
    provided = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if not provided or not secrets.compare_digest(provided, expected_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def _load_benchmark_overview() -> list[dict]:
    try:
        from benchmarks.summary import (
            latest_and_previous_results_by_target,
            load_findings_for_result,
            load_focus_findings_for_result,
            load_results,
            load_verdicts_for_result,
            module_counts,
            split_focus_module_counts,
        )
    except Exception:
        return []

    overview = []
    paired_results = latest_and_previous_results_by_target(load_results())
    for target_name in sorted(paired_results):
        result = paired_results[target_name]["latest"]
        previous = paired_results[target_name]["previous"]
        if not result:
            continue
        findings = load_findings_for_result(result)
        focus_findings = load_focus_findings_for_result(result)
        verdicts = load_verdicts_for_result(result)
        raw_counts = module_counts(findings)
        if focus_findings:
            focus_counts = module_counts(focus_findings, dedupe_by="family")
            focus_modules = {item.get("module_name") for item in focus_findings}
            background_counts = module_counts(
                [finding for finding in findings if finding.get("module_name") not in focus_modules],
                dedupe_by="family",
            )
        else:
            focus_counts, background_counts = split_focus_module_counts(
                findings,
                target_name,
                dedupe_by="family",
            )
        top_modules = [
            {"name": name, "count": count}
            for name, count in Counter(raw_counts).most_common(3)
        ]
        delta = {
            "findings": None,
            "confirmed_hit": None,
            "quiet_violation": None,
            "likely_false_positive": None,
            "changed_modules": [],
        }
        if previous:
            previous_findings = load_findings_for_result(previous)
            previous_verdicts = load_verdicts_for_result(previous)
            previous_module_counts = module_counts(previous_findings, dedupe_by="family")
            latest_module_counts = module_counts(findings, dedupe_by="family")
            delta["findings"] = (result.get("findings_count") or 0) - (previous.get("findings_count") or 0)
            delta["confirmed_hit"] = verdicts.get("verdict_counts", {}).get("confirmed_hit", 0) - previous_verdicts.get("verdict_counts", {}).get("confirmed_hit", 0)
            delta["quiet_violation"] = verdicts.get("verdict_counts", {}).get("quiet_violation", 0) - previous_verdicts.get("verdict_counts", {}).get("quiet_violation", 0)
            delta["likely_false_positive"] = verdicts.get("verdict_counts", {}).get("likely_false_positive", 0) - previous_verdicts.get("verdict_counts", {}).get("likely_false_positive", 0)
            delta["changed_modules"] = [
                {
                    "name": module_name,
                    "previous": previous_module_counts.get(module_name, 0),
                    "current": latest_module_counts.get(module_name, 0),
                }
                for module_name in sorted(set(previous_module_counts) | set(latest_module_counts))
                if previous_module_counts.get(module_name, 0) != latest_module_counts.get(module_name, 0)
            ]
        overview.append(
            {
                "target_name": result.get("target_name", target_name),
                "started_at": result.get("started_at", ""),
                "findings_count": result.get("findings_count", 0),
                "reachable": result.get("reachable", False),
                "return_code": result.get("return_code", "n/a"),
                "artifact_path": result.get("session_markdown_path", ""),
                "focus_artifact_path": result.get("focus_findings_json_path", ""),
                "focus_report_path": result.get("focus_report_markdown_path", ""),
                "verdict_counts": verdicts.get("verdict_counts", {}),
                "top_modules": top_modules,
                "focus_modules": [
                    {"name": name, "count": count}
                    for name, count in sorted(focus_counts.items(), key=lambda item: (-item[1], item[0]))
                ],
                "background_modules": [
                    {"name": name, "count": count}
                    for name, count in sorted(background_counts.items(), key=lambda item: (-item[1], item[0]))
                ],
                "delta": delta,
            }
        )
    return overview


def create_app(config: NightOwlConfig | None = None) -> FastAPI:
    app = FastAPI(title="NightOwl Dashboard", version="1.0.0")

    app.state.config = config or NightOwlConfig()

    # Security middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # CORS — restrict to localhost by default, configurable via env
    allowed_origins = os.environ.get("NIGHTOWL_CORS_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in allowed_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

    # Static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # API routes — protected by API key when configured
    app.include_router(api_router, prefix="/api", dependencies=[Depends(verify_api_key)])

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        from nightowl.db.database import Database
        from nightowl.modules import get_all_modules

        db = Database(app.state.config.db_path)
        await db.init()
        scans = await db.get_scans()
        modules = get_all_modules()
        maturity_counts = {
            "recommended": sum(1 for m in modules if m["maturity"] == "recommended"),
            "usable-with-caution": sum(1 for m in modules if m["maturity"] == "usable-with-caution"),
            "experimental": sum(1 for m in modules if m["maturity"] == "experimental"),
        }
        core_modules = [m for m in modules if m["core"]]
        benchmark_runs = _load_benchmark_overview()
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "scans": scans,
                "title": "NightOwl Dashboard",
                "maturity_counts": maturity_counts,
                "core_modules": core_modules,
                "benchmark_runs": benchmark_runs,
            },
        )

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_detail(request: Request, scan_id: str):
        from nightowl.db.database import Database
        db = Database(app.state.config.db_path)
        await db.init()
        findings = await db.get_findings(scan_id)
        stats = await db.get_finding_stats(scan_id)
        return templates.TemplateResponse(
            request=request,
            name="scan_detail.html",
            context={
                "scan_id": scan_id,
                "findings": findings,
                "stats": stats,
            },
        )

    return app
