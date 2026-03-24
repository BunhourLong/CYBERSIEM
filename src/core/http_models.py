from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class HTTPLogEvent:
    timestamp: datetime
    ip: str
    method: str
    endpoint: str
    status_code: int
    user_agent: str
    request_target: str
    raw_line: str
    query: str = ""
    referer: str = "-"


@dataclass(slots=True)
class DetectionAlert:
    ip: str
    endpoint: str
    alert_type: str
    severity: str
    timestamp: datetime
    message: str
    event_id: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

