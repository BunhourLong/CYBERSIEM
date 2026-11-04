from __future__ import annotations

import pytest

from src.security_engine.parser import LogParseError, parse_nginx_log_line


def _line(request: str, status: int = 200) -> str:
    return f'172.17.0.1 - a b [04/Nov/2026:00:59:25 +0000] "{request}" {status} 15 "-" "-" "-" "-" "172.17.0.1"'


@pytest.mark.parametrize(
    ("req", "method", "endpoint", "request_target"),
    [
        ("GET /b HTTP/1.1", "GET", "/b", "/b"),
        ("GET /h09 HTTP/1.1", "GET", "/h09", "/h09"),
        ("FOO_BAR /m1 HTTP/1.1", "FOO_BAR", "/m1", "/m1"),
        ("FOO-BAR /m2 HTTP/1.1", "FOO-BAR", "/m2", "/m2"),
        ("get /m3 HTTP/1.1", "GET", "/m3", "/m3"),
        ("GET /a b HTTP/1.1", "-", "/", "GET /a b HTTP/1.1"),
        ("\x16\x03\x01garbage", "-", "/", "\x16\x03\x01garbage"),
        ("GET /aaaa", "GET", "/aaaa", "/aaaa"),
        ("GET /h09", "GET", "/h09", "/h09"),
        ("GET //[x HTTP/1.1", "GET", "/[x", "//[x"),
        ("GET //.env HTTP/1.1", "GET", "/.env", "//.env"),
        ("GET http://evil/abs HTTP/1.1", "GET", "/abs", "http://evil/abs"),
        ("GET http://evil HTTP/1.1", "GET", "/", "http://evil"),
    ],
)
def test_client_controlled_requests_parse(req, method, endpoint, request_target):
    event = parse_nginx_log_line(_line(req))

    assert event.method == method
    assert event.endpoint == endpoint
    assert event.request_target == request_target
    assert event.status_code == 200
    assert event.ip == "172.17.0.1"


def test_normal_extended_line_is_unchanged():
    line = (
        "203.0.113.7 - - [04/Nov/2026:00:59:25 +0000] "
        '"GET /index.html HTTP/1.1" 404 0 "https://example.com" "curl/8" '
        '"203.0.113.7" "-" "10.0.0.2"'
    )

    event = parse_nginx_log_line(line)

    assert event.ip == "203.0.113.7"
    assert event.method == "GET"
    assert event.endpoint == "/index.html"
    assert event.status_code == 404
    assert event.referer == "https://example.com"
    assert event.user_agent == "curl/8"
    assert event.peer_ip == "10.0.0.2"
    assert event.ip_source == "x_forwarded_for"


def test_normal_combined_line_is_unchanged():
    line = '203.0.113.7 - - [04/Nov/2026:00:59:25 +0000] "GET /b HTTP/1.1" 200 15 "-" "curl/8"'

    event = parse_nginx_log_line(line)

    assert event.method == "GET"
    assert event.endpoint == "/b"
    assert event.user_agent == "curl/8"


def test_query_parameters_are_extracted():
    event = parse_nginx_log_line(_line("GET /search?q=test&page=2 HTTP/1.1"))

    assert event.endpoint == "/search"
    assert event.request_target == "/search?q=test&page=2"
    assert event.query == "q=test&page=2"


@pytest.mark.parametrize("line", ["not a log line", "", '172.17.0.1 - - "GET /" 200'])
def test_non_log_text_is_rejected(line):
    with pytest.raises(LogParseError):
        parse_nginx_log_line(line)


def test_dash_dash_user_parses():
    line = '1.2.3.4 - - - [04/Nov/2026:00:59:25 +0000] "GET /h09" 200 15 "-" "-"'
    assert parse_nginx_log_line(line).endpoint == "/h09"


def test_odd_user_never_raises_bare_value_error():
    line = '1.2.3.4 - a [b [04/Nov/2026:00:59:25 +0000] "GET / HTTP/1.1" 200 15 "-" "-"'
    try:
        parse_nginx_log_line(line)
    except LogParseError:
        pass


def test_bad_timestamp_raises_log_parse_error():
    line = '1.2.3.4 - - [99/Nov/2026:00:59:25 +0000] "GET / HTTP/1.1" 200 15 "-" "-"'
    with pytest.raises(LogParseError):
        parse_nginx_log_line(line)


@pytest.mark.parametrize(
    "req",
    ["POST  /login HTTP/1.1", "POST /login  HTTP/1.1", "POST /login HTTP/1.1  "],
)
def test_repeated_spaces_parse(req):
    event = parse_nginx_log_line(_line(req))
    assert (event.method, event.endpoint) == ("POST", "/login")


def test_method_is_uppercased():
    assert parse_nginx_log_line(_line("get /x HTTP/1.1")).method == "GET"


def test_long_method_is_clipped_and_payload_kept_in_query():
    event = parse_nginx_log_line(_line("A" * 17 + " /p?q=<script> HTTP/1.1"))
    assert event.method == "A" * 16
    assert event.query == "q=<script>"
