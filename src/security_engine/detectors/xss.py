from __future__ import annotations

import re
from urllib.parse import unquote_plus

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector


XSS_PATTERNS = [
    re.compile(r"(?i)<script[\s>]"),
    re.compile(r"(?i)</script\s*>"),
    re.compile(r"(?i)\bon\w+\s*="),
    re.compile(r"(?i)javascript\s*:"),
    re.compile(r"(?i)<\s*iframe[\s>]"),
    re.compile(r"(?i)eval\s*\("),
    re.compile(r"(?i)expression\s*\("),
    re.compile(r"(?i)document\.cookie"),
    re.compile(r"(?i)document\.write\s*\("),
    re.compile(r"(?i)<\s*img[^>]+onerror\s*="),
    re.compile(r"(?i)alert\s*\(\s*['\"]?[^)]{0,40}['\"]?\s*\)"),
]


class XSSPayloadDetector(Detector):
    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        normalized = unquote_plus(event.request_target)
        payload = f"{normalized} {event.user_agent}"
        matched = [p.pattern for p in XSS_PATTERNS if p.search(payload)]

        if not matched:
            return []

        confidence = min(95, 65 + len(matched) * 8)

        return [
            DetectionAlert(
                ip=event.ip,
                endpoint=event.endpoint,
                alert_type="xss_payload",
                severity="high",
                timestamp=event.timestamp,
                message=f"XSS payload detected from {event.ip}",
                confidence=confidence,
                metadata={"matched_patterns": matched},
            )
        ]
