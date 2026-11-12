from __future__ import annotations

import re
from urllib.parse import unquote_plus

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector

SQLI_PATTERNS = [
    re.compile(r"(?i)\bunion\b\s+\bselect\b"),
    re.compile(r"(?i)\bor\b\s+1=1\b"),
    re.compile(r"(?i)\bdrop\s+table\b"),
    re.compile(r"(?i)\binformation_schema\b"),
]

SQL_TERMINATOR = re.compile(r"([\"')\d;])\s*(--|/\*|\*/)\s*$")


class PayloadDetector(Detector):
    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        normalized_target = unquote_plus(event.request_target)
        payload = f"{normalized_target} {event.user_agent}"
        matched_patterns = [pattern.pattern for pattern in SQLI_PATTERNS if pattern.search(payload)]
        if SQL_TERMINATOR.search(normalized_target):
            matched_patterns.append(SQL_TERMINATOR.pattern)

        if not matched_patterns:
            return []

        return [
            DetectionAlert(
                ip=event.ip,
                endpoint=event.endpoint,
                alert_type="payload_sqli",
                severity="high",
                timestamp=event.timestamp,
                message=f"Suspicious SQLi payload detected from {event.ip}",
                metadata={"matched_patterns": matched_patterns},
            )
        ]
