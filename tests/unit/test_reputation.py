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


def test_manual_block_override_blocks_with_manual_reason(make_alert_row):
    previous = IPReputationRecord(ip=IP, analyst_override="manual_block")

    evaluation = evaluate_ip_reputation(IP, [], previous, now=NOW)

    assert evaluation.current_state == "blocked"
    assert evaluation.blocked_reason == "manual_block"
    assert evaluation.manual_blocked is True
    assert evaluation.reputation_reasons == ["manual_block_override"]


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


def test_block_window_keeps_ip_blocked_until_expiry(make_alert_row):
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


def test_direct_critical_branch_is_shadowed_by_alert_hold(make_alert_row):
    # A high-severity payload alert always sets the alert hold, which is checked first,
    # so the direct-critical branch never sets its own reason or block timer.
    evaluation = evaluate_ip_reputation(IP, [make_alert_row()], now=NOW)

    assert evaluation.blocked_reason == "alert_hold"
    assert evaluation.blocked_until is None
    assert "direct_critical_alert" not in evaluation.reputation_reasons


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
