"""CRUD repository layer for database operations."""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from nightowl.db.database import FindingTable, ScanTable, TargetTable

logger = logging.getLogger("nightowl")


class ScanRepository:
    def __init__(self, session: Session):
        self.db = session

    def create(self, scan_id: str, name: str, mode: str = "semi") -> ScanTable:
        row = ScanTable(id=scan_id, name=name, mode=mode, status="pending")
        self.db.add(row)
        self.db.commit()
        return row

    def get(self, scan_id: str) -> ScanTable | None:
        return self.db.query(ScanTable).filter_by(id=scan_id).first()

    def list_all(self, limit: int = 50) -> list[ScanTable]:
        return self.db.query(ScanTable).order_by(ScanTable.started_at.desc()).limit(limit).all()

    def update_status(self, scan_id: str, status: str) -> None:
        row = self.get(scan_id)
        if row:
            row.status = status
            if status == "running":
                row.started_at = datetime.now(timezone.utc)
            elif status in ("completed", "failed"):
                row.finished_at = datetime.now(timezone.utc)
            self.db.commit()

    def delete(self, scan_id: str) -> bool:
        row = self.get(scan_id)
        if row:
            self.db.delete(row)
            self.db.commit()
            return True
        return False


class FindingRepository:
    def __init__(self, session: Session):
        self.db = session

    def create(self, finding_data: dict) -> FindingTable:
        row = FindingTable(**finding_data)
        self.db.add(row)
        self.db.commit()
        return row

    def create_bulk(self, findings: list[dict]) -> int:
        for data in findings:
            self.db.add(FindingTable(**data))
        self.db.commit()
        return len(findings)

    def get_by_scan(self, scan_id: str) -> list[FindingTable]:
        return self.db.query(FindingTable).filter_by(scan_id=scan_id).all()

    def get_by_severity(self, severity: str) -> list[FindingTable]:
        return self.db.query(FindingTable).filter_by(severity=severity).all()

    def count(self, scan_id: str | None = None) -> int:
        q = self.db.query(FindingTable)
        if scan_id:
            q = q.filter_by(scan_id=scan_id)
        return q.count()


class TargetRepository:
    def __init__(self, session: Session):
        self.db = session

    def create(self, target_id: str, host: str, target_type: str = "ip") -> TargetTable:
        row = TargetTable(id=target_id, host=host, target_type=target_type)
        self.db.add(row)
        self.db.commit()
        return row

    def get(self, target_id: str) -> TargetTable | None:
        return self.db.query(TargetTable).filter_by(id=target_id).first()

    def list_all(self) -> list[TargetTable]:
        return self.db.query(TargetTable).all()

    def search(self, query: str) -> list[TargetTable]:
        return self.db.query(TargetTable).filter(
            TargetTable.host.contains(query)
        ).all()
