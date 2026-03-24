from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector


class RateAbuseDetector(Detector):
    def __init__(self, threshold: int = 30, window_seconds: int = 60) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._events_by_ip: dict[str, deque] = defaultdict(deque)
        self._last_alert_at: dict[str, object] = {}

    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        history = self._events_by_ip[event.ip]
        history.append(event.timestamp)

        while history and event.timestamp - history[0] > self.window:
            history.popleft()

        if len(history) < self.threshold:
            return []

        last_alert_at = self._last_alert_at.get(event.ip)
        if last_alert_at and event.timestamp - last_alert_at <= self.window:
            return []

        self._last_alert_at[event.ip] = event.timestamp

        return [
            DetectionAlert(
                ip=event.ip,
                endpoint=event.endpoint,
                alert_type="rate_abuse",
                severity="medium",
                timestamp=event.timestamp,
                message=f"{len(history)} requests from {event.ip} within {int(self.window.total_seconds())} seconds",
                metadata={
                    "request_count": len(history),
                    "window_seconds": int(self.window.total_seconds()),
                },
            )
        ]
