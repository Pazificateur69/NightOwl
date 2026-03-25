"""Vulnerability finding models."""

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """Represents a discovered vulnerability or security finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = ""
    category: str = ""
    target: str = ""
    port: int | None = None
    protocol: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    module_name: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    false_positive: bool = False
    metadata: dict = Field(default_factory=dict)

    @property
    def severity_color(self) -> str:
        colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange3",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "grey50",
        }
        return colors.get(self.severity, "white")


class FindingSummary(BaseModel):
    """Lightweight summary of a finding for list views."""

    id: str
    title: str
    severity: Severity
    cvss_score: float
    target: str
    module_name: str
    timestamp: datetime

    @classmethod
    def from_finding(cls, finding: Finding) -> "FindingSummary":
        return cls(
            id=finding.id,
            title=finding.title,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            target=finding.target,
            module_name=finding.module_name,
            timestamp=finding.timestamp,
        )
