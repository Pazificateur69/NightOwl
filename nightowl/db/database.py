"""SQLite database with SQLAlchemy (thread-pooled for async safety)."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, Boolean, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from nightowl.models.finding import Finding
from nightowl.models.scan import ScanSession

logger = logging.getLogger("nightowl")


class Base(DeclarativeBase):
    pass


class ScanTable(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    name = Column(String, default="")
    status = Column(String, default="pending")
    mode = Column(String, default="semi")
    targets_json = Column(Text, default="[]")
    modules_json = Column(Text, default="[]")
    findings_count = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    config_json = Column(Text, default="{}")


class FindingTable(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"), index=True)
    title = Column(String)
    description = Column(Text, default="")
    severity = Column(String, default="info")
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String, default="")
    category = Column(String, default="")
    target = Column(String, default="")
    port = Column(Integer, nullable=True)
    protocol = Column(String, default="")
    evidence = Column(Text, default="")
    remediation = Column(Text, default="")
    references_json = Column(Text, default="[]")
    module_name = Column(String, default="")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    false_positive = Column(Boolean, default=False)
    metadata_json = Column(Text, default="{}")


class ErrorTable(Base):
    __tablename__ = "scan_errors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id"), index=True)
    module_name = Column(String, default="")
    target = Column(String, default="")
    stage = Column(String, default="")
    error_message = Column(Text, default="")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class TargetTable(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True)
    host = Column(String)
    ip = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    target_type = Column(String, default="ip")
    domain = Column(String, nullable=True)


class Database:
    """Database manager for NightOwl.

    All public methods are async and offload blocking SQLAlchemy calls
    to a thread pool via asyncio.to_thread, avoiding event loop blocking.
    """

    def __init__(self, db_path: str = "./nightowl.db"):
        self.db_path = db_path
        self.engine = None
        self._session_factory = None
        self._write_lock = asyncio.Lock()

    async def init(self) -> None:
        await asyncio.to_thread(self._init_sync)

    def _init_sync(self) -> None:
        if self.db_path == ":memory:":
            from sqlalchemy.pool import StaticPool
            self.engine = create_engine(
                "sqlite:///:memory:",
                echo=False,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self.engine = create_engine(
                f"sqlite:///{self.db_path}",
                echo=False,
                connect_args={"check_same_thread": False},
            )

        # Enable WAL mode for better concurrent read/write performance
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

        Base.metadata.create_all(self.engine)
        self._session_factory = sessionmaker(bind=self.engine)
        logger.info(f"Database initialized at {self.db_path}")

    def _get_session(self) -> Session:
        return self._session_factory()

    # --- Scan CRUD ---

    async def save_scan(
        self,
        session: ScanSession,
        findings: list[Finding],
        errors: list[dict] | None = None,
    ) -> None:
        async with self._write_lock:
            await asyncio.to_thread(self._save_scan_sync, session, findings, errors or [])

    def _save_scan_sync(
        self, session: ScanSession, findings: list[Finding], errors: list[dict]
    ) -> None:
        with self._get_session() as db:
            # Upsert: update existing row if scan_id already exists
            existing = db.query(ScanTable).filter_by(id=session.id).first()
            if existing:
                existing.name = session.name
                existing.status = session.status.value
                existing.mode = session.mode.value
                existing.findings_count = len(findings)
                existing.started_at = session.started_at
                existing.finished_at = session.finished_at
                existing.modules_json = json.dumps(session.modules_enabled)
                existing.targets_json = json.dumps(
                    [t.model_dump(mode="json") for t in session.targets]
                )
                existing.config_json = json.dumps(session.config)
            else:
                scan_row = ScanTable(
                    id=session.id,
                    name=session.name,
                    status=session.status.value,
                    mode=session.mode.value,
                    targets_json=json.dumps(
                        [t.model_dump(mode="json") for t in session.targets]
                    ),
                    modules_json=json.dumps(session.modules_enabled),
                    findings_count=len(findings),
                    started_at=session.started_at,
                    finished_at=session.finished_at,
                    config_json=json.dumps(session.config),
                )
                db.add(scan_row)

            for f in findings:
                # Skip if finding already persisted
                if db.query(FindingTable).filter_by(id=f.id).first():
                    continue
                row = FindingTable(
                    id=f.id,
                    scan_id=session.id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity.value,
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    category=f.category,
                    target=f.target,
                    port=f.port,
                    protocol=f.protocol,
                    evidence=f.evidence,
                    remediation=f.remediation,
                    references_json=json.dumps(f.references),
                    module_name=f.module_name,
                    timestamp=f.timestamp,
                    false_positive=f.false_positive,
                    metadata_json=json.dumps({
                        **f.metadata,
                        "finding_state": f.finding_state.value,
                        "confidence_score": f.confidence_score,
                    }),
                )
                db.add(row)

            # Persist module errors
            for err in errors:
                duplicate_error = (
                    db.query(ErrorTable)
                    .filter_by(
                        scan_id=session.id,
                        module_name=err.get("module", ""),
                        target=err.get("target", ""),
                        stage=err.get("stage", ""),
                        error_message=err.get("error", ""),
                    )
                    .first()
                )
                if duplicate_error:
                    continue
                db.add(ErrorTable(
                    scan_id=session.id,
                    module_name=err.get("module", ""),
                    target=err.get("target", ""),
                    stage=err.get("stage", ""),
                    error_message=err.get("error", ""),
                ))

            db.commit()

    async def get_scans(self) -> list[dict]:
        return await asyncio.to_thread(self._get_scans_sync)

    def _get_scans_sync(self) -> list[dict]:
        with self._get_session() as db:
            rows = db.query(ScanTable).order_by(ScanTable.started_at.desc()).all()
            return [
                {
                    "id": r.id, "name": r.name, "status": r.status,
                    "mode": r.mode,
                    "findings_count": r.findings_count,
                    "started_at": str(r.started_at) if r.started_at else None,
                    "finished_at": str(r.finished_at) if r.finished_at else None,
                }
                for r in rows
            ]

    async def get_findings(self, scan_id: str) -> list[dict]:
        return await asyncio.to_thread(self._get_findings_sync, scan_id)

    def _get_findings_sync(self, scan_id: str) -> list[dict]:
        with self._get_session() as db:
            rows = db.query(FindingTable).filter_by(scan_id=scan_id).all()
            return [
                {
                    **{
                        "id": r.id, "title": r.title, "description": r.description,
                        "severity": r.severity, "cvss_score": r.cvss_score,
                        "cvss_vector": r.cvss_vector, "category": r.category,
                        "target": r.target, "port": r.port, "protocol": r.protocol,
                        "evidence": r.evidence, "remediation": r.remediation,
                        "references": json.loads(r.references_json or "[]"),
                        "module_name": r.module_name, "timestamp": str(r.timestamp),
                        "false_positive": r.false_positive,
                    },
                    "finding_state": json.loads(r.metadata_json or "{}").get("finding_state", "info"),
                    "confidence_score": json.loads(r.metadata_json or "{}").get("confidence_score", 0.5),
                    "metadata": json.loads(r.metadata_json or "{}"),
                }
                for r in rows
            ]

    async def get_finding_stats(self, scan_id: str) -> dict:
        return await asyncio.to_thread(self._get_finding_stats_sync, scan_id)

    def _get_finding_stats_sync(self, scan_id: str) -> dict:
        with self._get_session() as db:
            rows = db.query(FindingTable).filter_by(scan_id=scan_id).all()
            stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for r in rows:
                if r.severity in stats:
                    stats[r.severity] += 1
            return stats

    async def get_scan_errors(self, scan_id: str) -> list[dict]:
        return await asyncio.to_thread(self._get_scan_errors_sync, scan_id)

    def _get_scan_errors_sync(self, scan_id: str) -> list[dict]:
        with self._get_session() as db:
            rows = db.query(ErrorTable).filter_by(scan_id=scan_id).all()
            return [
                {
                    "scan_id": r.scan_id,
                    "module_name": r.module_name,
                    "target": r.target,
                    "stage": r.stage,
                    "error_message": r.error_message,
                    "timestamp": str(r.timestamp),
                }
                for r in rows
            ]
