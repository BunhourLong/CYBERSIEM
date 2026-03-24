from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AlertResponse(BaseModel):
    id: int
    event_id: int | None = None
    ip: str
    endpoint: str
    type: str
    severity: str
    status: str
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime | None = None


class MapPointResponse(BaseModel):
    ip: str
    lat: float
    lon: float
    severity: str
    type: str


class UpdateAlertStatusRequest(BaseModel):
    status: str


class BlockIPRequest(BaseModel):
    ip: str
    endpoint: str = "/"
    reason: str = "Manual block requested by analyst"
