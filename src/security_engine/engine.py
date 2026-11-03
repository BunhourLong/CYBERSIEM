from __future__ import annotations

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors import (
    BruteForceDetector,
    CredentialStuffingDetector,
    PathProbeDetector,
    PayloadDetector,
    RateAbuseDetector,
    ScrapingDetector,
    UserAgentRotationDetector,
    XSSPayloadDetector,
)
from src.security_engine.enforcement_service import EnforcementService
from src.security_engine.repository import SecurityRepository


class SecurityEngine:
    def __init__(
        self,
        repository: SecurityRepository | None = None,
        enforcement_service: EnforcementService | None = None,
    ) -> None:
        self.repository = repository or SecurityRepository()
        self.enforcement_service = enforcement_service or EnforcementService(repository=self.repository)
        self.detectors = [
            RateAbuseDetector(),
            BruteForceDetector(),
            PayloadDetector(),
            XSSPayloadDetector(),
            PathProbeDetector(),
            ScrapingDetector(),
            CredentialStuffingDetector(),
            UserAgentRotationDetector(),
        ]

    def process_event(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        event_id = self.repository.insert_event(event)
        alerts: list[DetectionAlert] = []

        for detector in self.detectors:
            alerts.extend(detector.evaluate(event))

        alert_ids_by_ip: dict[str, list[int]] = {}
        for alert in alerts:
            alert.event_id = event_id
            alert.id = self.repository.insert_alert(alert)
            alert_ids_by_ip.setdefault(alert.ip, []).append(alert.id)

        for ip, alert_ids in alert_ids_by_ip.items():
            self.enforcement_service.sync_ip_and_blocklist(
                ip,
                trigger_reason="new_alerts_detected",
                source_alert_ids=alert_ids,
                manual_or_auto="auto",
            )

        return alerts
