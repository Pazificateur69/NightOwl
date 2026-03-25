"""FastAPI web dashboard application."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from nightowl.models.config import NightOwlConfig
from nightowl.web.routers.api import router as api_router

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def create_app(config: NightOwlConfig | None = None) -> FastAPI:
    app = FastAPI(title="NightOwl Dashboard", version="1.0.0")

    app.state.config = config or NightOwlConfig()

    # Static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # API routes
    app.include_router(api_router, prefix="/api")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        from nightowl.db.database import Database
        db = Database(app.state.config.db_path)
        await db.init()
        scans = await db.get_scans()
        return templates.TemplateResponse("dashboard.html", {
            "request": request, "scans": scans, "title": "NightOwl Dashboard"
        })

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_detail(request: Request, scan_id: str):
        from nightowl.db.database import Database
        db = Database(app.state.config.db_path)
        await db.init()
        findings = await db.get_findings(scan_id)
        stats = await db.get_finding_stats(scan_id)
        return templates.TemplateResponse("scan_detail.html", {
            "request": request, "scan_id": scan_id,
            "findings": findings, "stats": stats,
        })

    return app
