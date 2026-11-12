from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector


class BruteForceDetector(Detector):
    def __init__(
        self,
        login_path: str = "/login",
        threshold: int = 5,
        window_seconds: int = 300,
    ) -> None:
        self.login_path = login_path
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._attempts_by_ip: dict[str, deque] = defaultdict(deque)
        self._failures_since_alert: dict[str, int] = defaultdict(int)

    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        if event.endpoint != self.login_path:
            return []

        attempts = self._attempts_by_ip[event.ip]
        attempts.append((event.timestamp, event.status_code))

        while attempts and event.timestamp - attempts[0][0] > self.window:
            attempts.popleft()

        failed_attempts = [status for _, status in attempts if status in {401, 403}]
        repeated_attempts = len(attempts)

        if event.status_code in {401, 403}:
            self._failures_since_alert[event.ip] += 1

        if len(failed_attempts) < self.threshold:
            return []

        if self._failures_since_alert[event.ip] < self.threshold:
            return []

        self._failures_since_alert[event.ip] = 0

        return [
            DetectionAlert(
                ip=event.ip,
                endpoint=event.endpoint,
                alert_type="brute_force",
                severity="medium",
                timestamp=event.timestamp,
                message=f"{repeated_attempts} login attempts detected for {event.ip}",
                metadata={
                    "attempt_count": repeated_attempts,
                    "failed_attempt_count": len(failed_attempts),
                    "window_seconds": int(self.window.total_seconds()),
                },
            )
        ]
