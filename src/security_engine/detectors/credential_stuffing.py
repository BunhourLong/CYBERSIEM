from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector

_AUTH_FAILURE_CODES = frozenset({401, 403})
_AUTH_PATH_FRAGMENTS = frozenset(
    {
        "login",
        "signin",
        "sign-in",
        "auth",
        "authenticate",
        "password",
        "token",
        "session",
        "wp-login",
    }
)


def _is_auth_endpoint(endpoint: str) -> bool:
    lower = endpoint.lower().rstrip("/")
    return any(frag in lower for frag in _AUTH_PATH_FRAGMENTS)


class CredentialStuffingDetector(Detector):
    """
    Distinguishes credential stuffing from brute force by detecting auth
    failures spread across multiple endpoints or accompanied by user-agent
    rotation — hallmarks of automated credential list attacks.
    """

    def __init__(
        self,
        failure_threshold: int = 10,
        multi_ua_threshold: int = 3,
        window_seconds: int = 300,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.multi_ua_threshold = multi_ua_threshold
        self.window = timedelta(seconds=window_seconds)
        self._failures_by_ip: dict[str, deque] = defaultdict(deque)
        self._last_alert_at: dict[str, object] = {}

    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        if event.status_code not in _AUTH_FAILURE_CODES:
            return []
        if not _is_auth_endpoint(event.endpoint):
            return []

        now = event.timestamp
        failures = self._failures_by_ip[event.ip]
        failures.append((now, event.endpoint, event.user_agent))

        while failures and now - failures[0][0] > self.window:
            failures.popleft()

        if len(failures) < self.failure_threshold:
            return []

        last_alert_at = self._last_alert_at.get(event.ip)
        if last_alert_at and now - last_alert_at <= self.window:
            return []

        unique_endpoints = len({ep for _, ep, _ in failures})
        unique_uas = len({ua for _, _, ua in failures})

        # Require at least multi-endpoint or multi-UA to distinguish from brute_force
        if unique_endpoints < 2 and unique_uas < self.multi_ua_threshold:
            return []

        self._last_alert_at[event.ip] = now
        severity = "high" if unique_uas >= self.multi_ua_threshold else "medium"
        confidence = min(92, 50 + unique_uas * 8 + unique_endpoints * 4)

        return [
            DetectionAlert(
                ip=event.ip,
                endpoint=event.endpoint,
                alert_type="credential_stuffing",
                severity=severity,
                timestamp=now,
                message=(
                    f"Credential stuffing from {event.ip}: "
                    f"{len(failures)} auth failures across {unique_endpoints} endpoint(s), "
                    f"{unique_uas} user agent(s)"
                ),
                confidence=confidence,
                metadata={
                    "failure_count": len(failures),
                    "unique_endpoints": unique_endpoints,
                    "unique_user_agents": unique_uas,
                    "window_seconds": int(self.window.total_seconds()),
                },
            )
        ]
