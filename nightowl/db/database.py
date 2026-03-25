"""SQLite database with SQLAlchemy."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, Boolean, create_engine
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
    scan_id = Column(String, index=True)
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


class TargetTable(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True)
    host = Column(String)
    ip = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    target_type = Column(String, default="ip")
    domain = Column(String, nullable=True)


class Database:
    """Database manager for NightOwl."""

    def __init__(self, db_path: str = "./nightowl.db"):
        self.db_path = db_path
        self.engine = None
        self._session_factory = None

    async def init(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{self.db_path}", echo=False)
        Base.metadata.create_all(self.engine)
        self._session_factory = sessionmaker(bind=self.engine)
        logger.info(f"Database initialized at {self.db_path}")

    def get_session(self) -> Session:
        return self._session_factory()

    async def save_scan(self, session: ScanSession, findings: list[Finding]) -> None:
        with self.get_session() as db:
            scan_row = ScanTable(
                id=session.id,
                name=session.name,
                status=session.status.value,
                mode=session.mode.value,
                targets_json=json.dumps([t.model_dump(mode="json") for t in session.targets]),
                modules_json=json.dumps(session.modules_enabled),
                findings_count=len(findings),
                started_at=session.started_at,
                finished_at=session.finished_at,
                config_json=json.dumps(session.config),
            )
            db.add(scan_row)

            for f in findings:
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
                    metadata_json=json.dumps(f.metadata),
                )
                db.add(row)

            db.commit()

    async def get_scans(self) -> list[dict]:
        with self.get_session() as db:
            rows = db.query(ScanTable).order_by(ScanTable.started_at.desc()).all()
            return [
                {
                    "id": r.id, "name": r.name, "status": r.status,
                    "findings_count": r.findings_count,
                    "started_at": str(r.started_at) if r.started_at else None,
                }
                for r in rows
            ]

    async def get_findings(self, scan_id: str) -> list[dict]:
        with self.get_session() as db:
            rows = db.query(FindingTable).filter_by(scan_id=scan_id).all()
            return [
                {
                    "id": r.id, "title": r.title, "severity": r.severity,
                    "cvss_score": r.cvss_score, "target": r.target,
                    "module_name": r.module_name, "evidence": r.evidence,
                    "remediation": r.remediation,
                }
                for r in rows
            ]

    async def get_finding_stats(self, scan_id: str) -> dict:
        with self.get_session() as db:
            rows = db.query(FindingTable).filter_by(scan_id=scan_id).all()
            stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for r in rows:
                if r.severity in stats:
                    stats[r.severity] += 1
            return stats
