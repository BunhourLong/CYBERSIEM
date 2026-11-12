from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.core.http_models import HTTPLogEvent
from src.security_engine.detectors.brute_force import BruteForceDetector
from src.security_engine.detectors.payload import PayloadDetector
from src.security_engine.detectors.xss import XSSPayloadDetector

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _event(
    target: str,
    *,
    ua: str = "Mozilla/5.0",
    status: int = 200,
    method: str = "GET",
    ip: str = "203.0.113.7",
    at: datetime = NOW,
) -> HTTPLogEvent:
    head, sep, tail = target.partition("?")
    return HTTPLogEvent(
        timestamp=at,
        ip=ip,
        method=method,
        endpoint=head,
        status_code=status,
        user_agent=ua,
        request_target=target,
        raw_line="",
        query=tail if sep else "",
    )


@pytest.mark.parametrize(
    "target",
    ["/products?online=1", "/products?only=true", "/products?onsale=1", "/products?once=1"],
)
def test_xss_ignores_ordinary_on_params(target):
    assert XSSPayloadDetector().evaluate(_event(target)) == []


def test_xss_ignores_alert_without_argument():
    assert XSSPayloadDetector().evaluate(_event("/search?q=how+to+use+alert()+in+javascript")) == []


@pytest.mark.parametrize(
    "target",
    [
        "/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
        "/search?q=%3Csvg/onload%3Dalert(1)%3E",
        "/p?name=x%22+onfocus%3Dfoo+autofocus+x%3D%22",
    ],
)
def test_xss_flags_real_handlers(target):
    result = XSSPayloadDetector().evaluate(_event(target))

    assert len(result) == 1
    assert result[0].alert_type == "xss_payload"


def test_xss_flags_breakout_with_unlisted_handler():
    result = XSSPayloadDetector().evaluate(_event("/p?name=x%22+onkeydown%3Dlocation%3D%27%2F%2Fevil%27"))

    assert len(result) == 1
    assert result[0].alert_type == "xss_payload"


def test_xss_flags_alert_with_expression_argument():
    result = XSSPayloadDetector().evaluate(_event("/search?q=alert(String.fromCharCode(88,83,83))"))

    assert len(result) == 1
    assert result[0].alert_type == "xss_payload"


def test_sqli_ignores_user_agent_ending_in_semicolon():
    event = _event("/", ua="Mozilla/5.0 (compatible; ExampleBot/1.0;")

    assert PayloadDetector().evaluate(event) == []
    assert XSSPayloadDetector().evaluate(event) == []


def test_sqli_ignores_target_ending_in_semicolon():
    assert PayloadDetector().evaluate(_event("/search?q=coffee;")) == []


def test_xss_flags_handler_at_value_start():
    result = XSSPayloadDetector().evaluate(_event("/p?name=onerror%3Dconfirm(1)"))

    assert len(result) == 1
    assert result[0].alert_type == "xss_payload"


def test_sqli_flags_terminator_in_target():
    result = PayloadDetector().evaluate(_event("/items?id=1;--"))

    assert len(result) == 1
    assert result[0].alert_type == "payload_sqli"


def test_sqli_flags_union_select():
    result = PayloadDetector().evaluate(_event("/items?id=1+UNION+SELECT+password+FROM+users"))

    assert len(result) == 1
    assert result[0].alert_type == "payload_sqli"


def test_brute_force_ignores_successful_logins():
    detector = BruteForceDetector()

    for i in range(5):
        assert detector.evaluate(_event("/login", status=200, at=NOW + timedelta(seconds=i))) == []


def test_brute_force_ignores_four_failures_and_a_success():
    detector = BruteForceDetector()

    for i in range(4):
        assert detector.evaluate(_event("/login", status=401, at=NOW + timedelta(seconds=i))) == []
    assert detector.evaluate(_event("/login", status=200, at=NOW + timedelta(seconds=4))) == []


def test_brute_force_flags_five_failures():
    detector = BruteForceDetector()

    for i in range(4):
        assert detector.evaluate(_event("/login", method="POST", status=401, at=NOW + timedelta(seconds=i))) == []
    result = detector.evaluate(_event("/login", method="POST", status=401, at=NOW + timedelta(seconds=4)))

    assert len(result) == 1
    assert result[0].alert_type == "brute_force"
    assert result[0].severity == "high"
