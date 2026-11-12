from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.security_engine.enforcement import IPReputationRecord, ReputationConfig, evaluate_ip_reputation

IP = "203.0.113.7"
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _path_probe_config(**overrides) -> ReputationConfig:
    # path_probe at medium severity stays below the alert-hold threshold.
    return ReputationConfig(alert_weights={"path_probe": 12.0}, **overrides)


def _path_probe_rows(make_alert_row, offsets_seconds: list[int]):
    return [
        make_alert_row(
            id=index + 1,
            type="path_probe",
            severity="medium",
            created_at=NOW - timedelta(seconds=offset),
        )
        for index, offset in enumerate(offsets_seconds)
    ]


def test_payload_sqli_alert_moves_ip_from_trusted_to_blocked(make_alert_row):
    evaluation = evaluate_ip_reputation(IP, [make_alert_row()], now=NOW)

    assert evaluation.old_state == "trusted"
    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "alert_hold"
    assert evaluation.reputation_reasons == ["alert_hold"]
    assert evaluation.current_score == pytest.approx(35.0)
    assert evaluation.block_count == 1
    assert evaluation.source_alert_ids == [1]


def test_whitelisted_ip_is_trusted_even_with_unresolved_alert(make_alert_row):
    previous = IPReputationRecord(ip=IP, whitelist=True)

    evaluation = evaluate_ip_reputation(IP, [make_alert_row()], previous, now=NOW)

    assert evaluation.current_state == "trusted"
    assert evaluation.blocked_reason is None
    assert evaluation.reputation_reasons == ["analyst_trusted_ip"]


def test_force_unblock_override_bypasses_alert_hold(make_alert_row):
    previous = IPReputationRecord(
        ip=IP,
        analyst_override="force_unblock",
        cooldown_until=NOW + timedelta(seconds=1800),
    )

    evaluation = evaluate_ip_reputation(IP, [make_alert_row()], previous, now=NOW)

    assert evaluation.current_state == "suspicious"
    assert evaluation.blocked_reason is None
    assert evaluation.blocked_until is None
    assert evaluation.analyst_override == "force_unblock"
    assert evaluation.reputation_reasons == ["force_unblock_override"]


def test_manual_block_override_blocks_with_manual_reason():
    previous = IPReputationRecord(ip=IP, analyst_override="manual_block")

    evaluation = evaluate_ip_reputation(IP, [], previous, now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "manual_block"
    assert evaluation.manual_blocked is True
    assert evaluation.reputation_reasons == ["manual_block_override"]


def test_safe_high_alert_does_not_hold_with_unrelated_low_unresolved_alert(make_alert_row):
    rows = [
        make_alert_row(id=1, type="payload_sqli", severity="high", status="safe"),
        make_alert_row(id=2, type="user_agent_rotation", severity="low", status="unresolved"),
    ]

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW)

    assert evaluation.current_state == "trusted"
    assert evaluation.blocked_reason is None
    assert evaluation.alert_hold_active is False


@pytest.mark.parametrize("status", ["unresolved", "malicious"])
def test_high_active_alert_holds_alongside_safe_alert(make_alert_row, status):
    rows = [
        make_alert_row(id=1, type="payload_sqli", severity="high", status="safe"),
        make_alert_row(id=2, type="payload_sqli", severity="high", status=status),
    ]

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "alert_hold"
    assert evaluation.alert_hold_active is True


def test_all_safe_alerts_release_alert_hold(make_alert_row):
    rows = [
        make_alert_row(id=1, type="payload_sqli", severity="high", status="safe"),
        make_alert_row(id=2, type="payload_sqli", severity="high", status="safe"),
    ]

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW)

    assert evaluation.current_state == "trusted"
    assert evaluation.blocked_reason is None
    assert evaluation.alert_hold_active is False


def test_alert_hold_blocks_and_clears_block_timer(make_alert_row):
    previous = IPReputationRecord(
        ip=IP,
        current_state="blocked",
        blocked_until=NOW + timedelta(seconds=3600),
    )

    evaluation = evaluate_ip_reputation(IP, [make_alert_row()], previous, now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "alert_hold"
    assert evaluation.blocked_until is None
    assert evaluation.alert_hold_active is True
    assert evaluation.reputation_reasons == ["alert_hold"]


def test_block_window_keeps_ip_blocked_until_expiry():
    block_until = NOW + timedelta(seconds=600)
    previous = IPReputationRecord(ip=IP, current_state="blocked", blocked_until=block_until)

    evaluation = evaluate_ip_reputation(IP, [], previous, now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "block_window_active"
    assert evaluation.blocked_until == block_until
    assert evaluation.reputation_reasons == ["block_window_active"]


def test_cooldown_throttles_repeated_medium_alerts(make_alert_row):
    rows = _path_probe_rows(make_alert_row, [120, 60, 0])
    previous = IPReputationRecord(ip=IP, cooldown_until=NOW + timedelta(seconds=1800))

    evaluation = evaluate_ip_reputation(IP, rows, previous, now=NOW, config=_path_probe_config())

    assert evaluation.current_state == "throttled"
    assert evaluation.blocked_reason is None
    assert evaluation.reputation_reasons == ["cooldown_active"]


def test_direct_critical_alert_blocks_with_block_timer_when_status_skips_alert_hold(make_alert_row):
    # Real rows can't reach this today: only unresolved, safe and malicious statuses exist.
    evaluation = evaluate_ip_reputation(IP, [make_alert_row(status="reviewing")], now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "direct_critical_alert"
    assert evaluation.blocked_until == NOW + timedelta(seconds=ReputationConfig().block_duration_seconds)
    assert evaluation.reputation_reasons == ["direct_critical_alert"]


def test_suppress_auto_block_during_cooldown_throttles_with_both_reasons(make_alert_row):
    rows = _path_probe_rows(make_alert_row, [120, 60, 0])
    previous = IPReputationRecord(
        ip=IP,
        analyst_override="suppress_auto_block",
        cooldown_until=NOW + timedelta(seconds=1800),
    )

    evaluation = evaluate_ip_reputation(IP, rows, previous, now=NOW, config=_path_probe_config())

    assert evaluation.current_state == "throttled"
    assert evaluation.blocked_reason is None
    assert evaluation.reputation_reasons == ["cooldown_active", "temporary_auto_block_suppression"]


def test_no_alerts_and_no_previous_record_is_trusted_with_no_reasons():
    evaluation = evaluate_ip_reputation(IP, [], now=NOW)

    assert evaluation.current_state == "trusted"
    assert evaluation.blocked_reason is None
    assert evaluation.reputation_reasons == []


def test_malicious_alert_adds_active_malicious_reason_after_alert_hold(make_alert_row):
    evaluation = evaluate_ip_reputation(IP, [make_alert_row(status="malicious")], now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "alert_hold"
    assert evaluation.reputation_reasons == ["alert_hold", "active_malicious_alerts"]


def test_whitelisted_ip_with_sustained_score_stays_trusted_and_reports_threshold(make_alert_row):
    rows = _path_probe_rows(make_alert_row, [240, 180, 120, 60, 0])
    previous = IPReputationRecord(ip=IP, whitelist=True)
    config = _path_probe_config(repeated_medium_min_weight=50.0)

    evaluation = evaluate_ip_reputation(IP, rows, previous, now=NOW, config=config)

    assert evaluation.current_score == pytest.approx(76.8)
    assert evaluation.current_state == "trusted"
    assert evaluation.blocked_reason is None
    assert evaluation.reputation_reasons == ["analyst_trusted_ip", "score_at_block_threshold"]


def test_three_medium_alerts_in_window_block_as_repeated_medium(make_alert_row):
    rows = _path_probe_rows(make_alert_row, [120, 60, 0])

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW, config=_path_probe_config())

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "repeated_medium_alerts"
    assert evaluation.blocked_until == NOW + timedelta(seconds=1800)
    assert evaluation.reputation_reasons == ["repeated_medium_alerts"]


def test_sustained_score_above_threshold_blocks(make_alert_row):
    # Five path_probe alerts give 12 + 4 * 16.2 = 76.8 (repeat multiplier 1.35).
    # repeated_medium_min_weight is raised so only the score can trigger the block.
    rows = _path_probe_rows(make_alert_row, [240, 180, 120, 60, 0])
    config = _path_probe_config(repeated_medium_min_weight=50.0)

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW, config=config)

    assert evaluation.current_score == pytest.approx(76.8)
    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "sustained_score_threshold"
    assert evaluation.blocked_until == NOW + timedelta(seconds=1800)
    assert evaluation.reputation_reasons == ["sustained_score_threshold"]


def test_single_medium_alert_reports_score_state(make_alert_row):
    rows = _path_probe_rows(make_alert_row, [0])

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW, config=_path_probe_config())

    assert evaluation.current_score == pytest.approx(12.0)
    assert evaluation.current_state == "unknown"
    assert evaluation.blocked_reason is None
    assert evaluation.reputation_reasons == ["score_state_unknown"]


def test_alert_hold_clears_on_previous_blocked_record_when_only_low_unresolved_remains(make_alert_row):
    previous = IPReputationRecord(ip=IP, current_state="blocked", blocked_reason="alert_hold", alert_hold_active=True)
    rows = [
        make_alert_row(id=1, type="payload_sqli", severity="high", status="safe"),
        make_alert_row(id=2, type="user_agent_rotation", severity="low", status="unresolved"),
    ]

    evaluation = evaluate_ip_reputation(IP, rows, previous, now=NOW)

    assert evaluation.blocked_reason != "alert_hold"
    assert evaluation.alert_hold_active is False
    assert "alert_hold" not in evaluation.reputation_reasons


def test_future_block_timer_survives_marking_its_alert_safe(make_alert_row):
    block_until = NOW + timedelta(seconds=3600)
    previous = IPReputationRecord(
        ip=IP,
        current_state="blocked",
        blocked_reason="sustained_score_threshold",
        blocked_until=block_until,
        alert_hold_active=False,
    )
    rows = [
        make_alert_row(id=1, type="payload_sqli", severity="high", status="safe"),
        make_alert_row(id=2, type="user_agent_rotation", severity="low", status="unresolved"),
    ]

    evaluation = evaluate_ip_reputation(IP, rows, previous, now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "sustained_score_threshold"
    assert evaluation.blocked_until == block_until
    assert evaluation.alert_hold_active is False
    assert evaluation.reputation_reasons == ["block_window_active"]


def test_safe_high_with_medium_unresolved_at_hold_weight_holds(make_alert_row):
    rows = [
        make_alert_row(id=1, type="payload_sqli", severity="high", status="safe"),
        make_alert_row(id=2, type="payload_sqli", severity="medium", status="unresolved"),
    ]

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "alert_hold"
    assert evaluation.alert_hold_active is True


def test_safe_high_with_malicious_low_below_hold_weight_does_not_hold(make_alert_row):
    rows = [
        make_alert_row(id=1, type="payload_sqli", severity="high", status="safe"),
        make_alert_row(id=2, type="user_agent_rotation", severity="low", status="malicious"),
    ]

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW)

    assert evaluation.blocked_reason != "alert_hold"
    assert evaluation.alert_hold_active is False
    assert "alert_hold" not in evaluation.reputation_reasons


def test_evaluation_does_not_depend_on_alert_row_order(make_alert_row):
    active = make_alert_row(
        id=1, type="payload_sqli", severity="high", status="unresolved", created_at=NOW - timedelta(seconds=60)
    )
    safe = make_alert_row(id=2, type="payload_sqli", severity="high", status="safe", created_at=NOW)

    active_first = evaluate_ip_reputation(IP, [active, safe], now=NOW)
    safe_first = evaluate_ip_reputation(IP, [safe, active], now=NOW)

    assert active_first == safe_first


def test_same_inputs_give_same_evaluation(make_alert_row):
    rows = [make_alert_row(id=1, type="payload_sqli", severity="high", status="unresolved")]
    previous = IPReputationRecord(ip=IP, current_state="blocked", blocked_reason="alert_hold")

    first = evaluate_ip_reputation(IP, rows, previous, now=NOW)
    second = evaluate_ip_reputation(IP, rows, previous, now=NOW)

    assert first == second


def test_one_brute_force_alert_does_not_block(make_alert_row):
    evaluation = evaluate_ip_reputation(IP, [make_alert_row(type="brute_force", severity="medium")], now=NOW)

    assert evaluation.current_state != "blocked"
    assert evaluation.blocked_reason is None
    assert evaluation.alert_hold_active is False


def test_three_brute_force_alerts_in_fifteen_minutes_block_with_expiry(make_alert_row):
    rows = [
        make_alert_row(id=1, type="brute_force", severity="medium", created_at=NOW - timedelta(seconds=600)),
        make_alert_row(id=2, type="brute_force", severity="medium", created_at=NOW - timedelta(seconds=300)),
        make_alert_row(id=3, type="brute_force", severity="medium", created_at=NOW),
    ]

    evaluation = evaluate_ip_reputation(IP, rows, now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "repeated_medium_alerts"
    assert evaluation.blocked_until == NOW + timedelta(seconds=1800)
    assert evaluation.alert_hold_active is False


def test_brute_force_resumed_after_block_expiry_blocks_again(make_alert_row):
    rows: list[dict] = []
    prev = None

    for index, offset in enumerate((0, 300, 600)):
        rows.append(
            make_alert_row(
                id=index + 1,
                type="brute_force",
                severity="medium",
                status="unresolved",
                created_at=NOW + timedelta(seconds=offset),
            )
        )
        prev = evaluate_ip_reputation(IP, rows, prev, now=NOW + timedelta(seconds=offset))

    assert prev.current_state == "blocked"
    assert prev.blocked_until == NOW + timedelta(seconds=2400)

    prev = evaluate_ip_reputation(IP, rows, prev, now=NOW + timedelta(seconds=2500))
    assert prev.current_state != "blocked"

    for index, offset in enumerate((2500, 2800, 3100), start=3):
        rows.append(
            make_alert_row(
                id=index + 1,
                type="brute_force",
                severity="medium",
                status="unresolved",
                created_at=NOW + timedelta(seconds=offset),
            )
        )
        prev = evaluate_ip_reputation(IP, rows, prev, now=NOW + timedelta(seconds=offset))

    assert prev.current_state == "blocked"


def test_alerts_raised_during_block_do_not_extend_it(make_alert_row):
    prev = IPReputationRecord(
        ip=IP,
        current_state="blocked",
        blocked_until=NOW + timedelta(seconds=1800),
        block_count=1,
        blocked_reason="repeated_medium_alerts",
    )
    rows = [
        make_alert_row(
            id=index + 1,
            type="brute_force",
            severity="medium",
            created_at=NOW + timedelta(seconds=offset),
        )
        for index, offset in enumerate((0, 300, 600, 1200, 1500, 1700))
    ]

    r1 = evaluate_ip_reputation(IP, rows, prev, now=NOW + timedelta(seconds=1800))
    assert r1.current_state != "blocked"

    r2 = evaluate_ip_reputation(IP, rows, r1, now=NOW + timedelta(seconds=1860))
    assert r2.current_state != "blocked"


def test_suppress_auto_block_still_holds_off_repeated_medium(make_alert_row):
    previous = IPReputationRecord(
        ip=IP,
        analyst_override="suppress_auto_block",
        cooldown_until=NOW + timedelta(seconds=1800),
    )
    rows = [
        make_alert_row(
            id=index + 1,
            type="rate_abuse",
            severity="medium",
            status="unresolved",
            created_at=NOW - timedelta(seconds=offset),
        )
        for index, offset in enumerate((600, 300, 0))
    ]

    evaluation = evaluate_ip_reputation(IP, rows, previous, now=NOW)

    assert evaluation.current_state == "throttled"
    assert "temporary_auto_block_suppression" in evaluation.reputation_reasons
