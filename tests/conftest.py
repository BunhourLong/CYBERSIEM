from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import create_autospec, patch

import pytest
from fastapi.testclient import TestClient

from src.core.http_models import HTTPLogEvent
from src.security_engine.repository import SecurityRepository

_fake = create_autospec(SecurityRepository, instance=True)


@pytest.fixture
def fake_repository():
    _fake.reset_mock(return_value=True, side_effect=True)
    return _fake


@pytest.fixture
def api_client(fake_repository):
    with patch("src.security_engine.repository.SecurityRepository", return_value=fake_repository):
        from src.api.main import app
    return TestClient(app)


@pytest.fixture
def make_http_event():
    def _make(**overrides):
        fields = {
            "timestamp": datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
            "ip": "203.0.113.7",
            "method": "GET",
            "endpoint": "/",
            "status_code": 200,
            "user_agent": "pytest",
            "request_target": "/",
            "raw_line": "",
        }
        fields.update(overrides)
        return HTTPLogEvent(**fields)

    return _make


@pytest.fixture
def make_alert_row():
    def _make(**overrides):
        row = {
            "id": 1,
            "type": "payload_sqli",
            "severity": "high",
            "status": "unresolved",
            "created_at": datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
            "metadata": {},
        }
        row.update(overrides)
        return row

    return _make
