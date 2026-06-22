from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, TypedDict
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NormalizedEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    source_type: str
    source_file: str
    event_type: str
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    host: str | None = None
    user: str | None = None
    signature: str | None = None
    severity: str = "Low"
    message: str
    raw_event: dict[str, Any] | str


class Incident(BaseModel):
    incident_uid: str = Field(default_factory=lambda: f"INC-{uuid4().hex[:12].upper()}")
    timestamp: datetime = Field(default_factory=utc_now)
    title: str
    incident_type: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    src_ip: str | None = None
    dest_ip: str | None = None
    affected_host: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    explanation: str = ""
    recommendation: str = ""
    evidence: list[str] = Field(default_factory=list)
    event_indexes: list[int] = Field(default_factory=list)
    report_path: str | None = None
    dashboard_summary: str = ""
    status: str = "open"


class Report(BaseModel):
    incident_uid: str
    path: str
    content: str
    summary: str


class ResponseAction(BaseModel):
    incident_uid: str
    timestamp: datetime = Field(default_factory=utc_now)
    action_type: str
    action_status: str = "SIMULATED_SUCCESS"
    details: str


class RunMetadata(BaseModel):
    run_uid: str = Field(default_factory=lambda: f"RUN-{uuid4().hex[:12].upper()}")
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    mode: str = "local"
    limit: int | None = None
    status: str = "running"


class SOCState(TypedDict, total=False):
    raw_events: list[dict[str, Any]]
    normalized_events: list[NormalizedEvent]
    incidents: list[Incident]
    reports: list[Report]
    actions: list[ResponseAction]
    errors: list[str]
    run_metadata: RunMetadata
