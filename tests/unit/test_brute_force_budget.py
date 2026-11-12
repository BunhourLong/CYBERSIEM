from __future__ import annotations

from datetime import timedelta

from src.security_engine.detectors.brute_force import BruteForceDetector
from src.security_engine.enforcement import evaluate_ip_reputation
from tests.unit.test_detectors import NOW, _event

IP = "203.0.113.7"


def _replay(times):
    """Feed failed-login events through one BruteForceDetector, and after each
    emitted alert evaluate IP reputation, carrying the previous record.

    Returns the 1-based attempt number at which is_blocked first became true,
    or None if it never did.
    """
    detector = BruteForceDetector()
    rows = []
    prev = None
    for attempt, t in enumerate(times, start=1):
        for alert in detector.evaluate(_event("/login", method="POST", status=401, ip=IP, at=t)):
            rows.append(
                {
                    "id": len(rows) + 1,
                    "type": alert.alert_type,
                    "severity": alert.severity,
                    "status": "unresolved",
                    "created_at": alert.timestamp,
                    "metadata": {},
                }
            )
            prev = evaluate_ip_reputation(IP, rows, prev, now=t)
            if prev.is_blocked:
                return attempt
    return None


def test_fifteen_fast_failures_block():
    times = [NOW + timedelta(seconds=i * 3) for i in range(20)]
    attempt = _replay(times)
    assert attempt is not None, f"never blocked; returned {attempt}"
    assert attempt <= 15, f"blocked at attempt {attempt}, expected <= 15"
