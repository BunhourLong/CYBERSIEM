from __future__ import annotations

import io
import os
import time
from pathlib import Path

from src.security_engine.engine import SecurityEngine
from src.security_engine.parser import LogParseError, parse_nginx_log_line


class LogMonitorService:
    IDLE_LOG_INTERVAL_SECONDS = 10.0
    MAX_LOG_LINE_PREVIEW_LENGTH = 200

    def __init__(self, engine: SecurityEngine | None = None) -> None:
        self.engine = engine or SecurityEngine()
        self.engine.enforcement_service.initialize()
        self._last_idle_log_at = 0.0

    def process_line(self, line: str):
        event = parse_nginx_log_line(line)
        alerts = self.engine.process_event(event)
        return event, alerts

    def run_forever(self, log_path: str) -> None:
        log_file = Path(log_path)
        self._log(f"Security engine started. Watching {log_file}")

        while True:
            if not log_file.exists():
                self._log_idle(log_file)
                time.sleep(1.0)
                continue

            try:
                with log_file.open("r", encoding="utf-8") as stream:
                    self._log(f"Opened log file: {log_file}")
                    self._seek_to_end(stream)
                    self._reset_idle_log_timer()

                    while True:
                        line = stream.readline()
                        if line:
                            self._reset_idle_log_timer()
                            self._log(f"Reading log line: {self._preview_line(line)}")
                            try:
                                event, alerts = self.process_line(line)
                            except LogParseError:
                                continue

                            self._log(
                                "Parsed event: "
                                f"ip={event.ip} source={event.ip_source} "
                                f"peer_ip={event.peer_ip} "
                                f"x_forwarded_for={event.x_forwarded_for} "
                                f"x_real_ip={event.x_real_ip} "
                                f"endpoint={event.endpoint}"
                            )

                            for alert in alerts:
                                self._log(
                                    "Alert triggered: "
                                    f"type={alert.alert_type} severity={alert.severity} "
                                    f"ip={alert.ip} endpoint={alert.endpoint}"
                                )
                            continue

                        if not log_file.exists():
                            self._log(
                                f"NGINX access log disappeared, waiting for {log_file}..."
                            )
                            self._reset_idle_log_timer()
                            break

                        self._log_idle(log_file)
                        time.sleep(0.5)
            except FileNotFoundError:
                self._log_idle(log_file)
                time.sleep(1.0)

    @staticmethod
    def _seek_to_end(stream) -> None:
        try:
            if stream.seekable():
                stream.seek(0, os.SEEK_END)
        except (io.UnsupportedOperation, OSError):
            return

    @staticmethod
    def _log(message: str) -> None:
        print(f"[security_engine] {message}", flush=True)

    @classmethod
    def _preview_line(cls, line: str) -> str:
        preview = line.strip()
        if len(preview) <= cls.MAX_LOG_LINE_PREVIEW_LENGTH:
            return preview
        return f"{preview[: cls.MAX_LOG_LINE_PREVIEW_LENGTH - 3]}..."

    def _log_idle(self, log_file: Path) -> None:
        now = time.monotonic()
        if now - self._last_idle_log_at < self.IDLE_LOG_INTERVAL_SECONDS:
            return

        self._last_idle_log_at = now
        self._log(f"Waiting for logs... path={log_file}")

    def _reset_idle_log_timer(self) -> None:
        self._last_idle_log_at = time.monotonic()


def main() -> None:
    log_path = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
    LogMonitorService().run_forever(log_path)


if __name__ == "__main__":
    main()
