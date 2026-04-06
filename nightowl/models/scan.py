"""Scan session and result models."""

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from nightowl.models.finding import Finding
from nightowl.models.target import Target


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanMode(str, Enum):
    AUTO = "auto"
    SEMI = "semi"
    MANUAL = "manual"


class ScanSession(BaseModel):
    """Represents a complete scan session."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = ""
    targets: list[Target] = Field(default_factory=list)
    status: ScanStatus = ScanStatus.PENDING
    mode: ScanMode = ScanMode.SEMI
    modules_enabled: list[str] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings_count: int = 0
    config: dict = Field(default_factory=dict)
    errors: list[dict] = Field(default_factory=list)
    module_status: list[dict] = Field(default_factory=list)

    def start(self) -> None:
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)

    def complete(self, findings_count: int = 0) -> None:
        self.status = ScanStatus.COMPLETED
        self.finished_at = datetime.now(timezone.utc)
        self.findings_count = findings_count

    def fail(self) -> None:
        self.status = ScanStatus.FAILED
        self.finished_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class ScanResult(BaseModel):
    """Result from a single module execution."""

    scan_id: str
    module_name: str
    findings: list[Finding] = Field(default_factory=list)
    duration_seconds: float = 0.0
    errors: list[str] = Field(default_factory=list)
    success: bool = True
