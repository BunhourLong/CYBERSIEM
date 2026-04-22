from __future__ import annotations

import os
import time
from datetime import datetime, timedelta

from src.security_engine.enforcement import (
    IPReputationRecord,
    NginxBlocklistManager,
    ReputationConfig,
    ReputationTransition,
    build_record_from_row,
    ensure_utc,
    evaluate_ip_reputation,
    utc_now,
)
from src.security_engine.repository import SecurityRepository


class EnforcementService:
    def __init__(
        self,
        repository: SecurityRepository | None = None,
        blocklist_manager: NginxBlocklistManager | None = None,
        config: ReputationConfig | None = None,
    ) -> None:
        self.repository = repository or SecurityRepository()
        self.blocklist_manager = blocklist_manager or NginxBlocklistManager()
        self.config = config or ReputationConfig()

    def initialize(self) -> None:
        retry_count = int(os.getenv("ENFORCEMENT_INIT_RETRIES", "30"))
        retry_delay_seconds = float(os.getenv("ENFORCEMENT_INIT_RETRY_DELAY_SECONDS", "1"))

        last_error: Exception | None = None
        for attempt in range(1, retry_count + 1):
            try:
                self.repository.ensure_schema()
                self.refresh_known_ip_states(trigger_reason="startup_refresh")
                self.sync_blocklist()
                return
            except Exception as exc:  # pragma: no cover - defensive startup retry
                last_error = exc
                if attempt == retry_count:
                    break
                time.sleep(retry_delay_seconds)

        if last_error is not None:
            raise last_error

    def refresh_known_ip_states(
        self,
        *,
        trigger_reason: str = "scheduled_refresh",
        manual_or_auto: str = "auto",
        now: datetime | None = None,
    ) -> list[dict]:
        records: list[dict] = []
        effective_now = ensure_utc(now) or utc_now()
        for ip in self.repository.list_known_ips():
            records.append(
                self.recalculate_ip_reputation(
                    ip,
                    trigger_reason=trigger_reason,
                    manual_or_auto=manual_or_auto,
                    now=effective_now,
                )
            )
        self.sync_blocklist()
        return records

    def recalculate_ip_reputation(
        self,
        ip: str,
        *,
        trigger_reason: str = "recalculated",
        source_alert_ids: list[int] | None = None,
        manual_or_auto: str = "auto",
        now: datetime | None = None,
    ) -> dict:
        effective_now = ensure_utc(now) or utc_now()
        previous_record = self._get_existing_record(ip)
        alert_rows = self.repository.list_alert_rows_for_ip(ip)
        ip_activity = self.repository.get_ip_activity(ip)

        evaluation = evaluate_ip_reputation(
            ip=ip,
            alert_rows=alert_rows,
            previous_record=previous_record,
            last_seen=ip_activity.get("last_seen"),
            now=effective_now,
            config=self.config,
            trigger_reason=trigger_reason,
            source_alert_ids=source_alert_ids,
        )
        stored_record = self.repository.upsert_ip_reputation(evaluation)

        if self._should_record_transition(previous_record, evaluation, manual_or_auto):
            self.repository.insert_reputation_transition(
                ReputationTransition(
                    ip=evaluation.ip,
                    old_state=previous_record.current_state,
                    new_state=evaluation.current_state,
                    score_before=previous_record.current_score,
                    score_after=evaluation.current_score,
                    trigger_reason=trigger_reason,
                    source_alert_ids=evaluation.source_alert_ids,
                    manual_or_auto=manual_or_auto,
                    created_at=effective_now,
                )
            )

        return stored_record

    def sync_ip_and_blocklist(
        self,
        ip: str,
        *,
        trigger_reason: str = "recalculated",
        source_alert_ids: list[int] | None = None,
        manual_or_auto: str = "auto",
        now: datetime | None = None,
    ) -> dict:
        record = self.recalculate_ip_reputation(
            ip,
            trigger_reason=trigger_reason,
            source_alert_ids=source_alert_ids,
            manual_or_auto=manual_or_auto,
            now=now,
        )
        self.sync_blocklist()
        return record

    def sync_blocklist(self) -> None:
        blocked_ips = [record["ip"] for record in self.repository.list_blocked_ips()]
        self.blocklist_manager.write_blocklist(blocked_ips)

    def update_alert_status(self, alert_id: int, status: str) -> dict | None:
        alert = self.repository.update_alert_status(alert_id, status)
        if not alert:
            return None

        self.sync_ip_and_blocklist(
            alert["ip"],
            trigger_reason=f"alert_status_changed:{status}",
            source_alert_ids=[alert_id],
            manual_or_auto="manual",
        )
        return self.repository.get_alert(alert_id)

    def manual_block_ip(self, ip: str, reason: str | None = None) -> dict:
        self.repository.set_ip_override_fields(
            ip,
            whitelist=False,
            analyst_override="manual_block",
            blocked_until=None,
            cooldown_until=None,
            blocked_reason=reason or "manual_block",
            manual_blocked=True,
        )
        return self.sync_ip_and_blocklist(
            ip,
            trigger_reason="manual_block_requested",
            manual_or_auto="manual",
        )

    def manual_unblock_ip(self, ip: str) -> dict:
        now = utc_now()
        self.repository.set_ip_override_fields(
            ip,
            whitelist=False,
            analyst_override="suppress_auto_block",
            blocked_until=None,
            cooldown_until=now + timedelta(seconds=self.config.cooldown_duration_seconds),
            blocked_reason=None,
            manual_blocked=False,
        )
        return self.sync_ip_and_blocklist(
            ip,
            trigger_reason="manual_unblock_requested",
            manual_or_auto="manual",
            now=now,
        )

    def trust_ip(self, ip: str, *, whitelist: bool = True) -> dict:
        self.repository.set_ip_override_fields(
            ip,
            whitelist=whitelist,
            analyst_override="trusted",
            blocked_until=None,
            cooldown_until=None,
            blocked_reason=None,
            manual_blocked=False,
        )
        return self.sync_ip_and_blocklist(
            ip,
            trigger_reason="analyst_trusted_ip",
            manual_or_auto="manual",
        )

    def remove_trust_ip(self, ip: str) -> dict:
        self.repository.set_ip_override_fields(
            ip,
            whitelist=False,
            analyst_override=None,
            blocked_until=None,
            cooldown_until=None,
            blocked_reason=None,
            manual_blocked=False,
        )
        return self.sync_ip_and_blocklist(
            ip,
            trigger_reason="analyst_removed_trust",
            manual_or_auto="manual",
        )

    def suppress_auto_block(
        self,
        ip: str,
        *,
        duration_seconds: int | None = None,
        whitelist: bool | None = None,
    ) -> dict:
        now = utc_now()
        existing = self._get_existing_record(ip)
        suppression_window = duration_seconds or self.config.suppress_duration_seconds
        self.repository.set_ip_override_fields(
            ip,
            whitelist=existing.whitelist if whitelist is None else whitelist,
            analyst_override="suppress_auto_block",
            blocked_until=None,
            cooldown_until=now + timedelta(seconds=max(1, suppression_window)),
            blocked_reason=None,
            manual_blocked=False,
        )
        return self.sync_ip_and_blocklist(
            ip,
            trigger_reason="temporary_auto_block_suppression",
            manual_or_auto="manual",
            now=now,
        )

    def clear_override(self, ip: str) -> dict:
        existing = self._get_existing_record(ip)
        self.repository.set_ip_override_fields(
            ip,
            whitelist=existing.whitelist,
            analyst_override=None,
            blocked_until=None,
            cooldown_until=None,
            blocked_reason=None,
            manual_blocked=False,
        )
        return self.sync_ip_and_blocklist(
            ip,
            trigger_reason="analyst_cleared_override",
            manual_or_auto="manual",
        )

    def apply_ip_control(
        self,
        ip: str,
        action: str,
        *,
        reason: str | None = None,
        duration_seconds: int | None = None,
    ) -> dict:
        if action == "manual_block":
            return self.manual_block_ip(ip, reason)
        if action == "manual_unblock":
            return self.manual_unblock_ip(ip)
        if action in {"trust", "whitelist"}:
            return self.trust_ip(ip, whitelist=action == "whitelist")
        if action in {"clear_trust", "unwhitelist"}:
            return self.remove_trust_ip(ip)
        if action == "suppress_auto_block":
            return self.suppress_auto_block(ip, duration_seconds=duration_seconds)
        if action == "clear_override":
            return self.clear_override(ip)

        raise ValueError(f"Unsupported IP control action: {action}")

    def _get_existing_record(self, ip: str) -> IPReputationRecord:
        existing_row = self.repository.get_ip_reputation(ip)
        return build_record_from_row(existing_row) or IPReputationRecord(ip=ip)

    @staticmethod
    def _should_record_transition(
        previous_record: IPReputationRecord,
        evaluation,
        manual_or_auto: str,
    ) -> bool:
        if previous_record.current_state != evaluation.current_state:
            return True
        if previous_record.analyst_override != evaluation.analyst_override:
            return True
        if previous_record.whitelist != evaluation.whitelist:
            return True
        if previous_record.blocked_until != evaluation.blocked_until:
            return True
        if previous_record.cooldown_until != evaluation.cooldown_until:
            return True
        if previous_record.blocked_reason != evaluation.blocked_reason:
            return True
        if manual_or_auto == "manual":
            return True
        return abs(previous_record.current_score - evaluation.current_score) >= 15
