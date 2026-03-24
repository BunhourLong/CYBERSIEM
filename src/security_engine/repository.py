from __future__ import annotations

import json
import os
from contextlib import contextmanager
from typing import Iterator

from psycopg import connect
from psycopg.rows import dict_row

from src.core.http_models import DetectionAlert, HTTPLogEvent


DEFAULT_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cybersiem:cybersiem@localhost:5432/cybersiem",
)


class SecurityRepository:
    def __init__(self, database_url: str = DEFAULT_DATABASE_URL) -> None:
        self.database_url = database_url

    @contextmanager
    def connection(self) -> Iterator:
        with connect(self.database_url, row_factory=dict_row) as conn:
            yield conn

    def insert_event(self, event: HTTPLogEvent) -> int:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO events (
                        occurred_at,
                        ip,
                        method,
                        endpoint,
                        status_code,
                        user_agent,
                        request_target,
                        query_string,
                        referer,
                        raw_line
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        event.timestamp,
                        event.ip,
                        event.method,
                        event.endpoint,
                        event.status_code,
                        event.user_agent,
                        event.request_target,
                        event.query,
                        event.referer,
                        event.raw_line,
                    ),
                )
                event_id = cur.fetchone()["id"]
            conn.commit()
        return event_id

    def insert_alert(self, alert: DetectionAlert) -> int:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO alerts (
                        event_id,
                        ip,
                        endpoint,
                        type,
                        severity,
                        status,
                        message,
                        metadata,
                        created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                    RETURNING id
                    """,
                    (
                        alert.event_id,
                        alert.ip,
                        alert.endpoint,
                        alert.alert_type,
                        alert.severity,
                        "open",
                        alert.message,
                        json.dumps(alert.metadata),
                        alert.timestamp,
                    ),
                )
                alert_id = cur.fetchone()["id"]
            conn.commit()
        return alert_id

    def list_alerts(self, limit: int = 100) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, event_id, host(ip) AS ip, endpoint, type, severity, status, message, metadata, created_at, updated_at
                    FROM alerts
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return list(cur.fetchall())

    def list_alert_map_rows(self, limit: int = 200) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT host(ip) AS ip, type, severity
                    FROM alerts
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return list(cur.fetchall())

    def get_alert(self, alert_id: int) -> dict | None:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, event_id, host(ip) AS ip, endpoint, type, severity, status, message, metadata, created_at, updated_at
                    FROM alerts
                    WHERE id = %s
                    """,
                    (alert_id,),
                )
                return cur.fetchone()

    def update_alert_status(self, alert_id: int, status: str) -> dict | None:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE alerts
                    SET status = %s, updated_at = NOW()
                    WHERE id = %s
                    RETURNING id, event_id, host(ip) AS ip, endpoint, type, severity, status, message, metadata, created_at, updated_at
                    """,
                    (status, alert_id),
                )
                row = cur.fetchone()
            conn.commit()
        return row
