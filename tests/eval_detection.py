"""Replay the labelled NGINX-log corpus through every detector: uv run --locked python -m tests.eval_detection."""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

from src.security_engine.detectors import Detector, build_detectors
from src.security_engine.enforcement import evaluate_ip_reputation
from src.security_engine.parser import LogParseError, parse_nginx_log_line

CORPUS = Path(__file__).parent / "corpus"


def _corpus_lines(path: Path):
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            yield lineno, stripped


def _parse_or_exit(path: Path, lineno: int, line: str):
    try:
        return parse_nginx_log_line(line)
    except LogParseError as exc:
        raise SystemExit(f"{path}:{lineno}: {exc}") from exc


def _evaluate(event, detectors: list[Detector]):
    alerts: list = []
    for detector in detectors:
        alerts.extend(detector.evaluate(event))
    return alerts


def _replay_attack(path: Path) -> tuple[list[tuple[int, str, set[str]]], dict[str, int], set[str]]:
    labelled: list[tuple[int, str, set[str]]] = []
    expected: dict[str, int] = defaultdict(int)
    fired_types: set[str] = set()
    detectors = build_detectors()

    for lineno, line in _corpus_lines(path):
        label, _, log_line = line.partition(" ")
        event = _parse_or_exit(path, lineno, log_line)
        fired = {alert.alert_type for alert in _evaluate(event, detectors)}
        fired_types |= fired
        if label != "-":
            expected[label] += 1
            labelled.append((lineno, label, fired))

    return labelled, expected, fired_types


def _replay_benign(path: Path) -> tuple[list[tuple[int, object, list]], int, set[str]]:
    lines: list[tuple[int, object, list]] = []
    fired_types: set[str] = set()
    detectors = build_detectors()

    for lineno, line in _corpus_lines(path):
        event = _parse_or_exit(path, lineno, line)
        alerts = _evaluate(event, detectors)
        fired_types |= {alert.alert_type for alert in alerts}
        lines.append((lineno, event, alerts))

    return lines, len(lines), fired_types


def run(benign_path: Path, attack_path: Path) -> int:
    labelled, expected, attack_fired = _replay_attack(attack_path)
    benign_events, benign_count, benign_fired = _replay_benign(benign_path)

    hits: dict[str, int] = defaultdict(int)
    for _, label, fired in labelled:
        if label in fired:
            hits[label] += 1

    for alert_type in sorted(set(expected) | attack_fired | benign_fired):
        false_positives = sum(1 for _, _, alerts in benign_events if any(a.alert_type == alert_type for a in alerts))
        print(
            f"{alert_type:<22} detected {hits[alert_type]}/{expected[alert_type]}"
            f"  false positives {false_positives}/{benign_count}"
        )

    for lineno, label, fired in labelled:
        if label not in fired:
            print(f"MISS {label} {attack_path.name}:{lineno}")

    for lineno, _, alerts in benign_events:
        for alert_type in sorted({alert.alert_type for alert in alerts}):
            print(f"FP {alert_type} {benign_path.name}:{lineno}")

    alerts_by_ip: dict[str, list] = defaultdict(list)
    previous_by_ip: dict[str, object] = {}
    blocked: dict[str, set[str]] = {}
    for _, event, alerts in benign_events:
        if not alerts:
            continue
        rows = alerts_by_ip.setdefault(event.ip, [])
        for alert in alerts:
            rows.append(
                {
                    "id": len(rows) + 1,
                    "type": alert.alert_type,
                    "severity": alert.severity,
                    "status": "unresolved",
                    "created_at": alert.timestamp,
                    "metadata": alert.metadata,
                }
            )
        result = evaluate_ip_reputation(
            event.ip, rows, previous_record=previous_by_ip.get(event.ip), now=event.timestamp
        )
        previous_by_ip[event.ip] = result
        if result.is_blocked:
            blocked.setdefault(event.ip, set()).update(alert.alert_type for alert in alerts)

    for ip in sorted(blocked):
        print(f"BLOCKED {ip} by {sorted(blocked[ip])}")

    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(run(CORPUS / "benign.txt", CORPUS / "attack.txt"))
