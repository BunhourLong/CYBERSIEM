from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlsplit

from src.core.http_models import HTTPLogEvent

NGINX_COMBINED_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/(?P<http_version>[^"]+)" '
    r'(?P<status>\d{3}) (?P<body_bytes_sent>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)


class LogParseError(ValueError):
    """Raised when an NGINX log line cannot be parsed."""


def parse_nginx_log_line(line: str) -> HTTPLogEvent:
    raw_line = line.strip()
    match = NGINX_COMBINED_LOG_PATTERN.match(raw_line)
    if not match:
        raise LogParseError(f"Unsupported NGINX log format: {raw_line}")

    target = match.group("target")
    parsed_target = urlsplit(target)
    endpoint = parsed_target.path or "/"

    return HTTPLogEvent(
        timestamp=datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z"),
        ip=match.group("ip"),
        method=match.group("method"),
        endpoint=endpoint,
        status_code=int(match.group("status")),
        user_agent=match.group("user_agent"),
        request_target=target,
        raw_line=raw_line,
        query=parsed_target.query,
        referer=match.group("referer"),
    )
