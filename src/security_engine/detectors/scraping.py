from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector


class ScrapingDetector(Detector):
    """
    Detects systematic scraping / API enumeration: high volume of successful
    GET requests to many unique endpoints in a short window.
    """

    def __init__(
        self,
        request_threshold: int = 50,
        unique_endpoint_threshold: int = 30,
        window_seconds: int = 60,
    ) -> None:
        self.request_threshold = request_threshold
        self.unique_endpoint_threshold = unique_endpoint_threshold
        self.window = timedelta(seconds=window_seconds)
        self._requests_by_ip: dict[str, deque] = defaultdict(deque)
        self._last_alert_at: dict[str, object] = {}

    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        if event.method != "GET":
            return []
        # Successful responses only — PathProbeDetector owns 404s
        if not (200 <= event.status_code < 400):
            return []

        now = event.timestamp
        history = self._requests_by_ip[event.ip]
        history.append((now, event.endpoint))

        while history and now - history[0][0] > self.window:
            history.popleft()

        if len(history) < self.request_threshold:
            return []

        unique_endpoints = len({ep for _, ep in history})
        if unique_endpoints < self.unique_endpoint_threshold:
            return []

        last_alert_at = self._last_alert_at.get(event.ip)
        if last_alert_at and now - last_alert_at <= self.window:
            return []

        self._last_alert_at[event.ip] = now
        diversity_ratio = unique_endpoints / max(1, len(history))
        confidence = min(90, int(50 + diversity_ratio * 55))

        return [
            DetectionAlert(
                ip=event.ip,
                endpoint=event.endpoint,
                alert_type="scraping",
                severity="medium",
                timestamp=now,
                message=(
                    f"Scraping detected from {event.ip}: "
                    f"{len(history)} GETs across {unique_endpoints} unique endpoints "
                    f"in {int(self.window.total_seconds())}s"
                ),
                confidence=confidence,
                metadata={
                    "request_count": len(history),
                    "unique_endpoint_count": unique_endpoints,
                    "window_seconds": int(self.window.total_seconds()),
                },
            )
        ]
