from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AlertResponse(BaseModel):
    id: int
    event_id: int | None = None
    ip: str
    ip_scope: str | None = None
    endpoint: str
    type: str
    severity: str
    status: str
    message: str
    confidence: int = 50
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    subdivision: str | None = None
    accuracy_radius_km: float | None = None
    reputation_status: str | None = None
    current_state: str | None = None
    current_score: float = 0
    lifetime_score: float = 0
    alert_count: int = 0
    malicious_count: int = 0
    block_count: int = 0
    offense_streak: int = 0
    last_seen: datetime | None = None
    last_alert_at: datetime | None = None
    blocked_until: datetime | None = None
    cooldown_until: datetime | None = None
    whitelist: bool = False
    analyst_override: str | None = None
    manual_blocked: bool = False
    blocked_reason: str | None = None
    threshold_reached: bool = False
    alert_hold_active: bool = False
    reputation_reasons: list[str] = Field(default_factory=list)
    block_countdown_seconds: int | None = None
    cooldown_countdown_seconds: int | None = None


class MapPointResponse(BaseModel):
    ip: str
    lat: float
    lon: float
    severity: str
    type: str
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    subdivision: str | None = None
    accuracy_radius_km: float | None = None
    organization: str | None = None
    is_hosting_provider: bool = False


class IngestEventRequest(BaseModel):
    timestamp: datetime | None = None
    ip: str | None = None
    method: str
    endpoint: str
    status_code: int
    user_agent: str = "-"
    request_target: str | None = None
    query: str = ""
    referer: str = "-"
    raw_line: str | None = None
    ip_source: str | None = None
    peer_ip: str | None = None
    x_forwarded_for: str | None = None
    x_real_ip: str | None = None
    cf_connecting_ip: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestedAlertResponse(BaseModel):
    id: int | None = None
    type: str
    severity: str
    message: str


class IngestEventResponse(BaseModel):
    ingested: bool = True
    ip: str
    ip_source: str
    alert_count: int
    alerts: list[IngestedAlertResponse] = Field(default_factory=list)


class BlockedIPResponse(BaseModel):
    ip: str
    reputation_status: str
    current_state: str | None = None
    current_score: float = 0
    lifetime_score: float = 0
    blocked_reason: str | None = None
    manual_blocked: bool = False
    block_count: int = 0
    offense_streak: int = 0
    blocked_until: datetime | None = None
    cooldown_until: datetime | None = None
    whitelist: bool = False
    analyst_override: str | None = None
    total_alert_count: int = 0
    safe_alert_count: int = 0
    unresolved_alert_count: int = 0
    malicious_alert_count: int = 0
    threshold_reached: bool = False
    alert_hold_active: bool = False
    unblock_eligible: bool = True
    reputation_reasons: list[str] = Field(default_factory=list)
    block_countdown_seconds: int | None = None
    cooldown_countdown_seconds: int | None = None
    updated_at: datetime | None = None


class UpdateAlertStatusRequest(BaseModel):
    status: Literal["unresolved", "safe", "malicious"]


class BlockIPRequest(BaseModel):
    ip: str
    endpoint: str = "/"
    reason: str = "Manual block requested by analyst"


class IPControlRequest(BaseModel):
    ip: str
    action: Literal[
        "manual_block",
        "manual_unblock",
        "force_unblock",
        "trust",
        "whitelist",
        "clear_trust",
        "unwhitelist",
        "suppress_auto_block",
        "clear_override",
    ]
    reason: str | None = None
    duration_seconds: int | None = None


class AlertTypeCount(BaseModel):
    type: str
    count: int


class SeverityCount(BaseModel):
    severity: str
    count: int


class TopIPEntry(BaseModel):
    ip: str
    alert_count: int
    current_state: str
    current_score: float


class AlertsPerHour(BaseModel):
    hour: datetime
    count: int


class DashboardStats(BaseModel):
    alert_type_counts: list[AlertTypeCount] = Field(default_factory=list)
    severity_counts: list[SeverityCount] = Field(default_factory=list)
    top_ips: list[TopIPEntry] = Field(default_factory=list)
    alerts_per_hour: list[AlertsPerHour] = Field(default_factory=list)
    hours_window: int = 24
