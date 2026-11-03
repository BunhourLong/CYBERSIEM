from __future__ import annotations

import pytest

TOKEN = "s3cret"
BODY = {"ip": "203.0.113.7", "method": "GET", "endpoint": "/", "status_code": 200}


@pytest.fixture
def client(api_client, monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", TOKEN)
    return api_client


def _auth(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def test_missing_token_is_401_and_writes_nothing(client, fake_repository):
    assert client.post("/ingest-event", json=BODY).status_code == 401
    assert fake_repository.mock_calls == []


def test_bad_body_without_token_is_401_not_422(client):
    assert client.post("/ingest-event", json={}).status_code == 401


@pytest.mark.parametrize("header", ["Bearer wrong", "s3cret", "Bearer ", "Basic s3cret"])
def test_wrong_token_is_401(client, fake_repository, header):
    assert client.post("/ingest-event", json=BODY, headers={"Authorization": header}).status_code == 401
    assert fake_repository.mock_calls == []


@pytest.mark.parametrize("value", [None, ""])
def test_unset_or_empty_token_turns_the_route_off(api_client, monkeypatch, value):
    if value is None:
        monkeypatch.delenv("INGEST_TOKEN", raising=False)
    else:
        monkeypatch.setenv("INGEST_TOKEN", value)
    assert api_client.post("/ingest-event", json=BODY, headers=_auth("")).status_code == 503
    assert api_client.post("/ingest-event", json=BODY, headers=_auth()).status_code == 503


def test_right_token_is_202(client, monkeypatch):
    from src.api import main

    monkeypatch.setattr(main.security_engine, "process_event", lambda event: [])
    assert client.post("/ingest-event", json=BODY, headers=_auth()).status_code == 202


@pytest.mark.parametrize(
    "ts", ["2020-01-01T00:00:00Z", "2999-01-01T00:00:00", "0001-01-01T00:00:00", "9999-12-31T23:59:59Z"]
)
def test_far_timestamp_is_rejected(client, monkeypatch, ts):
    from src.api import main

    monkeypatch.setattr(main.security_engine, "process_event", lambda event: pytest.fail("processed"))
    response = client.post("/ingest-event", json={**BODY, "timestamp": ts}, headers=_auth())
    assert response.status_code == 422


def test_non_finite_timestamp_is_rejected(client):
    response = client.post(
        "/ingest-event",
        content='{"method":"GET","endpoint":"/","status_code":200,"timestamp":1e999}',
        headers={**_auth(), "content-type": "application/json"},
    )
    assert response.status_code == 422


def test_recent_naive_timestamp_is_accepted(client, monkeypatch):
    from datetime import datetime, timezone

    from src.api import main

    monkeypatch.setattr(main.security_engine, "process_event", lambda event: [])
    ts = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    assert client.post("/ingest-event", json={**BODY, "timestamp": ts}, headers=_auth()).status_code == 202
