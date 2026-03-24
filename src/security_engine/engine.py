from __future__ import annotations

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors import (
    BruteForceDetector,
    PayloadDetector,
    RateAbuseDetector,
)
from src.security_engine.repository import SecurityRepository


class SecurityEngine:
    def __init__(self, repository: SecurityRepository | None = None) -> None:
        self.repository = repository or SecurityRepository()
        self.detectors = [
            RateAbuseDetector(),
            BruteForceDetector(),
            PayloadDetector(),
        ]

    def process_event(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        event_id = self.repository.insert_event(event)
        alerts: list[DetectionAlert] = []

        for detector in self.detectors:
            alerts.extend(detector.evaluate(event))

        for alert in alerts:
            alert.event_id = event_id
            self.repository.insert_alert(alert)

        return alerts
