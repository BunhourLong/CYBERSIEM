from __future__ import annotations

import re
from datetime import datetime
from ipaddress import ip_address
from urllib.parse import urlsplit

from src.core.http_models import HTTPLogEvent

NGINX_COMBINED_LOG_PATTERN = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/(?P<http_version>[^"]+)" '
    r"(?P<status>\d{3}) (?P<body_bytes_sent>\d+|-) "
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

NGINX_EXTENDED_LOG_PATTERN = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/(?P<http_version>[^"]+)" '
    r"(?P<status>\d{3}) (?P<body_bytes_sent>\d+|-) "
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" '
    r'"(?P<x_forwarded_for>[^"]*)" "(?P<x_real_ip>[^"]*)" "(?P<peer_ip>[^"]*)"$'
)


class LogParseError(ValueError):
    """Raised when an NGINX log line cannot be parsed."""


def _extract_forwarded_ips(raw_value: str) -> list[str]:
    if not raw_value or raw_value == "-":
        return []

    ips: list[str] = []
    for value in raw_value.split(","):
        candidate = value.strip()
        if not candidate or candidate == "-":
            continue
        try:
            ip_address(candidate)
        except ValueError:
            continue
        ips.append(candidate)
    return ips


def _detect_ip_source(client_ip: str, x_forwarded_for: str, x_real_ip: str) -> str:
    forwarded_ips = _extract_forwarded_ips(x_forwarded_for)
    if client_ip in forwarded_ips:
        return "x_forwarded_for"

    if x_real_ip and x_real_ip != "-":
        try:
            if ip_address(client_ip) == ip_address(x_real_ip):
                return "x_real_ip"
        except ValueError:
            pass

    return "remote_addr"


def parse_nginx_log_line(line: str) -> HTTPLogEvent:
    raw_line = line.strip()
    match = NGINX_EXTENDED_LOG_PATTERN.match(raw_line)
    if not match:
        match = NGINX_COMBINED_LOG_PATTERN.match(raw_line)
    if not match:
        raise LogParseError(f"Unsupported NGINX log format: {raw_line}")

    x_forwarded_for = match.groupdict().get("x_forwarded_for", "-") or "-"
    x_real_ip = match.groupdict().get("x_real_ip", "-") or "-"
    peer_ip = match.groupdict().get("peer_ip", "-") or "-"
    target = match.group("target")
    parsed_target = urlsplit(target)
    endpoint = parsed_target.path or "/"
    client_ip = match.group("ip")

    return HTTPLogEvent(
        timestamp=datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z"),
        ip=client_ip,
        method=match.group("method"),
        endpoint=endpoint,
        status_code=int(match.group("status")),
        user_agent=match.group("user_agent"),
        request_target=target,
        raw_line=raw_line,
        query=parsed_target.query,
        referer=match.group("referer"),
        ip_source=_detect_ip_source(client_ip, x_forwarded_for, x_real_ip),
        peer_ip=peer_ip,
        x_forwarded_for=x_forwarded_for,
        x_real_ip=x_real_ip,
    )
