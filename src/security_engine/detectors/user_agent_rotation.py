from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector


_GENERIC_BOT_PREFIXES = (
    "python-requests",
    "curl/",
    "wget/",
    "go-http-client",
    "java/",
    "okhttp",
    "libwww-perl",
    "httpie",
    "axios/",
    "aiohttp/",
    "scrapy/",
    "pycurl",
)


def _is_generic_bot(ua: str) -> bool:
    lower = ua.lower()
    return any(lower.startswith(p) for p in _GENERIC_BOT_PREFIXES)


class UserAgentRotationDetector(Detector):
    """
    Detects evasion via user-agent cycling: an IP cycling through many
    distinct user agents within a short window (bot-framework signature).
    """

    def __init__(
        self,
        ua_threshold: int = 5,
        window_seconds: int = 300,
    ) -> None:
        self.ua_threshold = ua_threshold
        self.window = timedelta(seconds=window_seconds)
        self._uas_by_ip: dict[str, deque] = defaultdict(deque)
        self._last_alert_at: dict[str, object] = {}

    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        ua = event.user_agent.strip()
        if not ua or ua == "-":
            return []

        now = event.timestamp
        history = self._uas_by_ip[event.ip]
        history.append((now, ua))

        while history and now - history[0][0] > self.window:
            history.popleft()

        unique_uas = {u for _, u in history}
        if len(unique_uas) < self.ua_threshold:
            return []

        last_alert_at = self._last_alert_at.get(event.ip)
        if last_alert_at and now - last_alert_at <= self.window:
            return []

        self._last_alert_at[event.ip] = now
        has_bot_ua = any(_is_generic_bot(u) for u in unique_uas)
        severity = "high" if has_bot_ua else "medium"
        confidence = min(88, 45 + len(unique_uas) * 7)

        return [
            DetectionAlert(
                ip=event.ip,
                endpoint=event.endpoint,
                alert_type="user_agent_rotation",
                severity=severity,
                timestamp=now,
                message=(
                    f"User-agent rotation from {event.ip}: "
                    f"{len(unique_uas)} distinct agents in {int(self.window.total_seconds())}s"
                ),
                confidence=confidence,
                metadata={
                    "unique_ua_count": len(unique_uas),
                    "has_generic_bot_ua": has_bot_ua,
                    "window_seconds": int(self.window.total_seconds()),
                    "sample_uas": list(unique_uas)[:5],
                },
            )
        ]
