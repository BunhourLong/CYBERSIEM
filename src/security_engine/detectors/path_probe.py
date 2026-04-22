from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector


class PathProbeDetector(Detector):
    """Detects 404 spray and directory/path probing."""

    def __init__(
        self,
        spray_threshold: int = 15,
        probe_request_threshold: int = 20,
        probe_unique_path_threshold: int = 10,
        window_seconds: int = 120,
    ) -> None:
        self.spray_threshold = spray_threshold
        self.probe_request_threshold = probe_request_threshold
        self.probe_unique_path_threshold = probe_unique_path_threshold
        self.window = timedelta(seconds=window_seconds)
        self._404s_by_ip: dict[str, deque] = defaultdict(deque)
        self._requests_by_ip: dict[str, deque] = defaultdict(deque)
        self._last_alert_at: dict[str, object] = {}

    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        now = event.timestamp

        if event.status_code == 404:
            q404 = self._404s_by_ip[event.ip]
            q404.append((now, event.endpoint))
            while q404 and now - q404[0][0] > self.window:
                q404.popleft()

        all_reqs = self._requests_by_ip[event.ip]
        all_reqs.append((now, event.endpoint))
        while all_reqs and now - all_reqs[0][0] > self.window:
            all_reqs.popleft()

        last_alert_at = self._last_alert_at.get(event.ip)
        if last_alert_at and now - last_alert_at <= self.window:
            return []

        # 404 spray: burst of not-found responses
        if event.status_code == 404:
            recent_404s = self._404s_by_ip[event.ip]
            if len(recent_404s) >= self.spray_threshold:
                unique_paths = len({ep for _, ep in recent_404s})
                confidence = min(95, 60 + unique_paths * 2)
                self._last_alert_at[event.ip] = now
                return [
                    DetectionAlert(
                        ip=event.ip,
                        endpoint=event.endpoint,
                        alert_type="404_spray",
                        severity="medium",
                        timestamp=now,
                        message=(
                            f"{len(recent_404s)} 404 responses from {event.ip} "
                            f"in {int(self.window.total_seconds())}s "
                            f"({unique_paths} unique paths)"
                        ),
                        confidence=confidence,
                        metadata={
                            "404_count": len(recent_404s),
                            "unique_path_count": unique_paths,
                            "window_seconds": int(self.window.total_seconds()),
                        },
                    )
                ]

        # Path probe: broad endpoint enumeration
        unique_endpoints = {ep for _, ep in all_reqs}
        if (
            len(all_reqs) >= self.probe_request_threshold
            and len(unique_endpoints) >= self.probe_unique_path_threshold
        ):
            confidence = min(90, 50 + len(unique_endpoints) * 2)
            self._last_alert_at[event.ip] = now
            return [
                DetectionAlert(
                    ip=event.ip,
                    endpoint=event.endpoint,
                    alert_type="path_probe",
                    severity="medium",
                    timestamp=now,
                    message=(
                        f"Path probing from {event.ip}: "
                        f"{len(unique_endpoints)} unique endpoints in {int(self.window.total_seconds())}s"
                    ),
                    confidence=confidence,
                    metadata={
                        "request_count": len(all_reqs),
                        "unique_endpoint_count": len(unique_endpoints),
                        "window_seconds": int(self.window.total_seconds()),
                    },
                )
            ]

        return []
