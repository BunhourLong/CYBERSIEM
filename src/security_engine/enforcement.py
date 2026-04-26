from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


ALERT_STATUSES = ("unresolved", "safe", "malicious")
REPUTATION_STATES = ("trusted", "unknown", "suspicious", "throttled", "blocked")
ANALYST_OVERRIDE_VALUES = (
    "manual_block",
    "trusted",
    "suppress_auto_block",
    "force_unblock",
)

# Alerts with weight >= this threshold (or severity == "high") trigger an alert hold:
# the IP stays blocked until every alert for that IP is marked safe.
ALERT_HOLD_MIN_WEIGHT = 20.0

DEFAULT_STATE_THRESHOLDS = {
    "trusted": 0.0,
    "unknown": 10.0,
    "suspicious": 25.0,
    "throttled": 45.0,
    "blocked": 70.0,
}
DEFAULT_ALERT_WEIGHTS = {
    "rate_abuse": 10.0,
    "brute_force": 20.0,
    "payload_sqli": 35.0,
    "sqli_high_confidence": 35.0,
    "path_probe": 12.0,
    "404_spray": 10.0,
    "xss_payload": 18.0,
    "header_anomaly": 8.0,
    "credential_stuffing": 25.0,
    "scraping": 12.0,
    "user_agent_rotation": 8.0,
    "manual_block": 0.0,
}
DEFAULT_SEVERITY_WEIGHTS = {
    "high": 18.0,
    "medium": 10.0,
    "low": 6.0,
}
DEFAULT_NGINX_BLOCKLIST_PATH = os.getenv(
    "NGINX_BLOCKLIST_PATH",
    "/shared-nginx/blocklist.conf",
)


def _parse_json_object_env(name: str, default: dict[str, float]) -> dict[str, float]:
    raw_value = os.getenv(name)
    if not raw_value:
        return dict(default)

    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return dict(default)

    if not isinstance(parsed, dict):
        return dict(default)

    result = dict(default)
    for key, value in parsed.items():
        try:
            result[str(key)] = float(value)
        except (TypeError, ValueError):
            continue
    return result


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_float_env(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return float(raw_value)
    except ValueError:
        return default


def _parse_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _round_score(value: float) -> float:
    return round(float(value), 2)


@dataclass(slots=True)
class ReputationConfig:
    score_thresholds: dict[str, float] = field(
        default_factory=lambda: _parse_json_object_env(
            "REPUTATION_STATE_THRESHOLDS",
            DEFAULT_STATE_THRESHOLDS,
        )
    )
    alert_weights: dict[str, float] = field(
        default_factory=lambda: _parse_json_object_env(
            "REPUTATION_ALERT_WEIGHTS",
            DEFAULT_ALERT_WEIGHTS,
        )
    )
    severity_weights: dict[str, float] = field(
        default_factory=lambda: _parse_json_object_env(
            "REPUTATION_SEVERITY_WEIGHTS",
            DEFAULT_SEVERITY_WEIGHTS,
        )
    )
    repeat_window_seconds: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_REPEAT_WINDOW_SECONDS", 900)
    )
    repeat_multiplier_step: float = field(
        default_factory=lambda: _parse_float_env("REPUTATION_REPEAT_MULTIPLIER_STEP", 0.35)
    )
    repeat_multiplier_cap: float = field(
        default_factory=lambda: _parse_float_env("REPUTATION_REPEAT_MULTIPLIER_CAP", 2.5)
    )
    decay_grace_seconds: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_DECAY_GRACE_SECONDS", 900)
    )
    decay_per_hour: float = field(
        default_factory=lambda: _parse_float_env("REPUTATION_DECAY_PER_HOUR", 8.0)
    )
    streak_reset_seconds: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_STREAK_RESET_SECONDS", 3600)
    )
    repeated_medium_alert_count: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_REPEATED_MEDIUM_ALERT_COUNT", 3)
    )
    repeated_medium_window_seconds: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_REPEATED_MEDIUM_WINDOW_SECONDS", 900)
    )
    repeated_medium_min_weight: float = field(
        default_factory=lambda: _parse_float_env("REPUTATION_REPEATED_MEDIUM_MIN_WEIGHT", 10.0)
    )
    direct_block_min_weight: float = field(
        default_factory=lambda: _parse_float_env("REPUTATION_DIRECT_BLOCK_MIN_WEIGHT", 35.0)
    )
    direct_block_window_seconds: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_DIRECT_BLOCK_WINDOW_SECONDS", 1800)
    )
    block_duration_seconds: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_BLOCK_DURATION_SECONDS", 1800)
    )
    cooldown_duration_seconds: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_COOLDOWN_DURATION_SECONDS", 1800)
    )
    suppress_duration_seconds: int = field(
        default_factory=lambda: _parse_int_env("REPUTATION_SUPPRESS_DURATION_SECONDS", 3600)
    )
    auto_decay_enabled: bool = field(
        default_factory=lambda: _parse_bool(os.getenv("REPUTATION_AUTO_DECAY_ENABLED"), True)
    )

    def __post_init__(self) -> None:
        for state in REPUTATION_STATES:
            self.score_thresholds.setdefault(state, DEFAULT_STATE_THRESHOLDS[state])
        self.score_thresholds = {
            state: float(self.score_thresholds[state]) for state in REPUTATION_STATES
        }

        for severity, value in DEFAULT_SEVERITY_WEIGHTS.items():
            self.severity_weights.setdefault(severity, value)
        self.severity_weights = {
            str(key): float(value) for key, value in self.severity_weights.items()
        }

    @property
    def blocked_threshold(self) -> float:
        return self.score_thresholds["blocked"]

    @property
    def throttled_threshold(self) -> float:
        return self.score_thresholds["throttled"]

    @property
    def suspicious_threshold(self) -> float:
        return self.score_thresholds["suspicious"]

    @property
    def unknown_threshold(self) -> float:
        return self.score_thresholds["unknown"]

    def state_for_score(self, score: float) -> str:
        if score >= self.blocked_threshold:
            return "blocked"
        if score >= self.throttled_threshold:
            return "throttled"
        if score >= self.suspicious_threshold:
            return "suspicious"
        if score >= self.unknown_threshold:
            return "unknown"
        return "trusted"

    def weight_for_alert(self, alert_type: str, severity: str) -> float:
        if alert_type in self.alert_weights:
            return float(self.alert_weights[alert_type])
        return float(self.severity_weights.get(severity, self.severity_weights["medium"]))


@dataclass(slots=True)
class AlertEvidence:
    alert_id: int | None
    alert_type: str
    severity: str
    status: str
    created_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IPReputationRecord:
    ip: str
    current_score: float = 0.0
    lifetime_score: float = 0.0
    alert_count: int = 0
    malicious_count: int = 0
    block_count: int = 0
    offense_streak: int = 0
    current_state: str = "trusted"
    reputation_status: str = "trusted"
    last_seen: datetime | None = None
    last_alert_at: datetime | None = None
    blocked_until: datetime | None = None
    cooldown_until: datetime | None = None
    whitelist: bool = False
    analyst_override: str | None = None
    blocked_reason: str | None = None
    manual_blocked: bool = False
    threshold_reached: bool = False
    total_alert_count: int = 0
    safe_alert_count: int = 0
    unresolved_alert_count: int = 0
    malicious_alert_count: int = 0
    alert_hold_active: bool = False
    updated_at: datetime | None = None
    reputation_reasons: list[str] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.current_state == "blocked"


@dataclass(slots=True)
class IPReputationEvaluation(IPReputationRecord):
    score_before: float = 0.0
    old_state: str = "trusted"
    source_alert_ids: list[int] = field(default_factory=list)
    trigger_reason: str = "recalculated"


@dataclass(slots=True)
class ReputationTransition:
    ip: str
    old_state: str
    new_state: str
    score_before: float
    score_after: float
    trigger_reason: str
    source_alert_ids: list[int] = field(default_factory=list)
    manual_or_auto: str = "auto"
    created_at: datetime = field(default_factory=utc_now)


def build_record_from_row(row: dict | None) -> IPReputationRecord | None:
    if not row:
        return None

    return IPReputationRecord(
        ip=row["ip"],
        current_score=float(row.get("current_score") or 0.0),
        lifetime_score=float(row.get("lifetime_score") or 0.0),
        alert_count=int(row.get("alert_count") or row.get("total_alert_count") or 0),
        malicious_count=int(row.get("malicious_count") or 0),
        block_count=int(row.get("block_count") or 0),
        offense_streak=int(row.get("offense_streak") or 0),
        current_state=row.get("current_state") or row.get("reputation_status") or "trusted",
        reputation_status=row.get("current_state") or row.get("reputation_status") or "trusted",
        last_seen=ensure_utc(row.get("last_seen")),
        last_alert_at=ensure_utc(row.get("last_alert_at")),
        blocked_until=ensure_utc(row.get("blocked_until")),
        cooldown_until=ensure_utc(row.get("cooldown_until")),
        whitelist=bool(row.get("whitelist", False)),
        analyst_override=row.get("analyst_override"),
        blocked_reason=row.get("blocked_reason"),
        manual_blocked=bool(row.get("manual_blocked", False)),
        threshold_reached=bool(row.get("threshold_reached", False)),
        total_alert_count=int(row.get("total_alert_count") or row.get("alert_count") or 0),
        safe_alert_count=int(row.get("safe_alert_count") or 0),
        unresolved_alert_count=int(row.get("unresolved_alert_count") or 0),
        malicious_alert_count=int(row.get("malicious_alert_count") or row.get("malicious_count") or 0),
        alert_hold_active=bool(row.get("alert_hold_active", False)),
        updated_at=ensure_utc(row.get("updated_at")),
        reputation_reasons=list(row.get("reputation_reasons") or []),
    )


def _as_alert_evidence(row: dict) -> AlertEvidence:
    return AlertEvidence(
        alert_id=row.get("id"),
        alert_type=row["type"],
        severity=row["severity"],
        status=row["status"],
        created_at=ensure_utc(row["created_at"]) or utc_now(),
        metadata=dict(row.get("metadata") or {}),
    )


def _decayed_score(weight: float, event_time: datetime, now: datetime, config: ReputationConfig) -> float:
    if not config.auto_decay_enabled:
        return _round_score(weight)

    age_seconds = max(0.0, (now - event_time).total_seconds())
    if age_seconds <= config.decay_grace_seconds:
        return _round_score(weight)

    decay_seconds = age_seconds - config.decay_grace_seconds
    decay_amount = (config.decay_per_hour / 3600.0) * decay_seconds
    return _round_score(max(0.0, weight - decay_amount))


def _repeat_multiplier(streak_size: int, config: ReputationConfig) -> float:
    if streak_size <= 1:
        return 1.0

    multiplier = 1.0 + ((streak_size - 1) * config.repeat_multiplier_step)
    return min(multiplier, config.repeat_multiplier_cap)


def _max_state(left: str, right: str) -> str:
    return left if REPUTATION_STATES.index(left) >= REPUTATION_STATES.index(right) else right


def evaluate_ip_reputation(
    ip: str,
    alert_rows: list[dict],
    previous_record: IPReputationRecord | None = None,
    *,
    last_seen: datetime | None = None,
    now: datetime | None = None,
    config: ReputationConfig | None = None,
    trigger_reason: str = "recalculated",
    source_alert_ids: list[int] | None = None,
) -> IPReputationEvaluation:
    config = config or ReputationConfig()
    now = ensure_utc(now) or utc_now()
    previous_record = previous_record or IPReputationRecord(ip=ip)

    alert_evidence = sorted((_as_alert_evidence(row) for row in alert_rows), key=lambda item: item.created_at)
    safe_alert_count = sum(1 for alert in alert_evidence if alert.status == "safe")
    unresolved_alert_count = sum(1 for alert in alert_evidence if alert.status == "unresolved")
    malicious_alert_count = sum(1 for alert in alert_evidence if alert.status == "malicious")
    alert_count = len(alert_evidence)

    # Hold is active when any non-safe alert meets the actionable threshold.
    # It clears only when every alert for this IP has been marked safe.
    new_alert_hold = (unresolved_alert_count > 0 or malicious_alert_count > 0) and any(
        config.weight_for_alert(a.alert_type, a.severity) >= ALERT_HOLD_MIN_WEIGHT
        or a.severity == "high"
        for a in alert_evidence
    )

    current_score = 0.0
    lifetime_score = 0.0
    offense_streak = 0
    repeated_medium_count = 0
    critical_alert_ids: list[int] = []
    contributing_alert_ids: list[int] = []
    recent_active_alerts: list[AlertEvidence] = []
    previous_active_alert_time: datetime | None = None

    for alert in alert_evidence:
        base_weight = config.weight_for_alert(alert.alert_type, alert.severity)
        is_active = alert.status != "safe"
        if is_active and previous_active_alert_time is not None:
            within_repeat_window = (
                alert.created_at - previous_active_alert_time
            ).total_seconds() <= config.repeat_window_seconds
        else:
            within_repeat_window = False

        alert_streak = 1
        if is_active and within_repeat_window:
            alert_streak = offense_streak + 1 if offense_streak > 0 else 2

        multiplier = _repeat_multiplier(alert_streak if is_active else 1, config)
        weighted_score = _round_score(base_weight * multiplier)
        lifetime_score += weighted_score

        if not is_active:
            continue

        previous_active_alert_time = alert.created_at
        recent_active_alerts.append(alert)
        if alert.alert_id is not None:
            contributing_alert_ids.append(alert.alert_id)
        current_score += _decayed_score(weighted_score, alert.created_at, now, config)

        if now - alert.created_at <= timedelta(seconds=config.repeated_medium_window_seconds):
            if base_weight >= config.repeated_medium_min_weight:
                repeated_medium_count += 1

        if (
            base_weight >= config.direct_block_min_weight
            and alert.severity == "high"
            and now - alert.created_at <= timedelta(seconds=config.direct_block_window_seconds)
            and alert.alert_id is not None
        ):
            critical_alert_ids.append(alert.alert_id)

    if recent_active_alerts:
        offense_streak = 1
        latest_time = recent_active_alerts[-1].created_at
        if now - latest_time > timedelta(seconds=config.streak_reset_seconds):
            offense_streak = 0
        else:
            previous_time = latest_time
            for alert in reversed(recent_active_alerts[:-1]):
                if previous_time - alert.created_at <= timedelta(seconds=config.repeat_window_seconds):
                    offense_streak += 1
                    previous_time = alert.created_at
                else:
                    break
    else:
        offense_streak = 0

    current_score = _round_score(current_score)
    lifetime_score = _round_score(lifetime_score)
    raw_state = config.state_for_score(current_score)
    threshold_reached = current_score >= config.blocked_threshold

    blocked_until = previous_record.blocked_until
    cooldown_until = previous_record.cooldown_until
    analyst_override = previous_record.analyst_override
    whitelist = previous_record.whitelist
    last_alert_at = alert_evidence[-1].created_at if alert_evidence else previous_record.last_alert_at
    last_seen = ensure_utc(last_seen) or previous_record.last_seen
    reasons: list[str] = []
    blocked_reason: str | None = None
    current_state = raw_state

    if analyst_override == "suppress_auto_block" and cooldown_until and cooldown_until <= now:
        analyst_override = None
        cooldown_until = None

    if analyst_override == "force_unblock" and cooldown_until and cooldown_until <= now:
        analyst_override = None
        cooldown_until = None

    if blocked_until and blocked_until <= now and previous_record.current_state == "blocked":
        blocked_until = None
        if cooldown_until is None or cooldown_until <= now:
            cooldown_until = now + timedelta(seconds=config.cooldown_duration_seconds)

    alert_hold_active = False
    has_direct_critical = bool(critical_alert_ids)
    has_repeated_medium = repeated_medium_count >= config.repeated_medium_alert_count
    sustained_block_score = current_score >= config.blocked_threshold
    auto_block_eligible = has_direct_critical or has_repeated_medium or sustained_block_score
    force_block = has_direct_critical or has_repeated_medium

    if whitelist or analyst_override == "trusted":
        current_state = "trusted"
        blocked_until = None
        blocked_reason = None
        reasons.append("analyst_trusted_ip")
    elif analyst_override == "force_unblock" and cooldown_until and cooldown_until > now:
        # Admin-forced release: bypasses alert hold and score-based auto-block for the cooldown window.
        current_state = config.state_for_score(current_score)
        blocked_until = None
        blocked_reason = None
        reasons.append("force_unblock_override")
    elif analyst_override == "manual_block":
        current_state = "blocked"
        blocked_reason = previous_record.blocked_reason or "manual_block"
        alert_hold_active = new_alert_hold
        reasons.append("manual_block_override")
    elif new_alert_hold:
        # Alert hold: IP stays blocked until every alert is reviewed and marked safe.
        current_state = "blocked"
        blocked_until = None  # no timer expiry — cleared only by alert review
        blocked_reason = "alert_hold"
        alert_hold_active = True
        reasons.append("alert_hold")
    elif blocked_until and blocked_until > now:
        current_state = "blocked"
        blocked_reason = previous_record.blocked_reason or "block_window_active"
        reasons.append("block_window_active")
    elif cooldown_until and cooldown_until > now and auto_block_eligible and not has_direct_critical:
        current_state = "throttled"
        blocked_reason = None
        reasons.append("cooldown_active")
        if analyst_override == "suppress_auto_block":
            reasons.append("temporary_auto_block_suppression")
    elif has_direct_critical:
        current_state = "blocked"
        blocked_until = now + timedelta(seconds=config.block_duration_seconds)
        blocked_reason = "direct_critical_alert"
        reasons.append("direct_critical_alert")
    elif has_repeated_medium:
        current_state = "blocked"
        blocked_until = now + timedelta(seconds=config.block_duration_seconds)
        blocked_reason = "repeated_medium_alerts"
        reasons.append("repeated_medium_alerts")
    elif auto_block_eligible and (force_block or raw_state == "blocked"):
        current_state = "blocked"
        blocked_until = now + timedelta(seconds=config.block_duration_seconds)
        blocked_reason = "sustained_score_threshold"
        reasons.append("sustained_score_threshold")
    else:
        current_state = raw_state
        blocked_reason = None
        if raw_state != "trusted":
            reasons.append(f"score_state_{raw_state}")

    if malicious_alert_count > 0:
        reasons.append("active_malicious_alerts")

    if threshold_reached and "sustained_score_threshold" not in reasons and current_state != "blocked":
        reasons.append("score_at_block_threshold")

    manual_blocked = analyst_override == "manual_block"
    block_count = int(previous_record.block_count or 0)
    if previous_record.current_state != "blocked" and current_state == "blocked":
        block_count += 1

    effective_source_alert_ids = [alert_id for alert_id in (source_alert_ids or []) if alert_id is not None]
    if not effective_source_alert_ids:
        if has_direct_critical:
            effective_source_alert_ids = critical_alert_ids
        else:
            effective_source_alert_ids = contributing_alert_ids[-5:]

    return IPReputationEvaluation(
        ip=ip,
        current_score=current_score,
        lifetime_score=lifetime_score,
        alert_count=alert_count,
        malicious_count=malicious_alert_count,
        block_count=block_count,
        offense_streak=offense_streak,
        current_state=current_state,
        reputation_status=current_state,
        last_seen=last_seen,
        last_alert_at=last_alert_at,
        blocked_until=blocked_until,
        cooldown_until=cooldown_until,
        whitelist=whitelist,
        analyst_override=analyst_override,
        blocked_reason=blocked_reason,
        manual_blocked=manual_blocked,
        threshold_reached=threshold_reached,
        total_alert_count=alert_count,
        safe_alert_count=safe_alert_count,
        unresolved_alert_count=unresolved_alert_count,
        malicious_alert_count=malicious_alert_count,
        alert_hold_active=alert_hold_active,
        updated_at=now,
        reputation_reasons=list(dict.fromkeys(reasons)),
        score_before=_round_score(previous_record.current_score),
        old_state=previous_record.current_state,
        source_alert_ids=effective_source_alert_ids,
        trigger_reason=trigger_reason,
    )


class NginxBlocklistManager:
    def __init__(self, blocklist_path: str = DEFAULT_NGINX_BLOCKLIST_PATH) -> None:
        self.blocklist_path = Path(blocklist_path)

    def ensure_exists(self) -> None:
        self.blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.blocklist_path.exists():
            self.blocklist_path.write_text(
                "# Managed by CyberSIEM. Do not edit manually.\n",
                encoding="utf-8",
            )

    def write_blocklist(self, blocked_ips: list[str]) -> None:
        self.ensure_exists()

        lines = ["# Managed by CyberSIEM. Do not edit manually."]
        lines.extend(f"deny {ip};" for ip in sorted(set(blocked_ips)))
        payload = "\n".join(lines) + "\n"

        current = ""
        try:
            current = self.blocklist_path.read_text(encoding="utf-8")
        except OSError:
            current = ""

        if current == payload:
            return

        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=str(self.blocklist_path.parent),
        ) as temp_file:
            temp_file.write(payload)
            temp_path = Path(temp_file.name)

        temp_path.replace(self.blocklist_path)
