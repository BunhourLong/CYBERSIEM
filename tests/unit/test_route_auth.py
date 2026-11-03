from __future__ import annotations

import pytest
from fastapi.routing import APIRoute
from starlette.routing import Route

from src.api.auth import create_session_cookie

# Anonymous access is allowed only here. Anything else must answer 401.
PUBLIC = {
    ("POST", "/login"),  # login form
    ("POST", "/api/auth/login"),  # login form
    ("POST", "/logout"),  # clears own cookie
    ("POST", "/api/auth/logout"),  # clears own cookie
    ("GET", "/health"),  # liveness probe
    ("GET", "/"),  # UI shell (JSON status for non-HTML clients)
    ("GET", "/login"),  # UI shell
    ("GET", "/dashboard"),  # UI shell, data comes from guarded /api/ui/*
    ("GET", "/denied"),  # UI shell
    ("POST", "/ingest-event"),  # temporary, removed by T-003
}
# Minimal body valid for every POST/PATCH route, so validation cannot hide a missing guard.
BODY = {"ip": "203.0.113.7", "status": "safe", "action": "block"}


def _routes():
    for route in api_routes():
        for method in route.methods - {"HEAD", "OPTIONS"}:
            yield method, route.path


def api_routes():
    from src.api.main import app

    return [r for r in app.routes if isinstance(r, (APIRoute, Route))]


def test_every_route_requires_auth_unless_allowlisted(api_client):
    for method, path in _routes():
        if (method, path) in PUBLIC:
            continue
        url = path.replace("{alert_id}", "1").replace("{ip}", "203.0.113.7")
        response = api_client.request(method, url, json=BODY if method in ("POST", "PATCH") else None)
        assert response.status_code == 401, f"{method} {path} answered {response.status_code} anonymously"


def test_api_docs_are_off_by_default(api_client):
    paths = {path for _, path in _routes()}
    assert not paths & {"/docs", "/redoc", "/openapi.json"}


@pytest.fixture
def readonly_client(api_client, fake_repository, monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    fake_repository.get_user_by_id.return_value = {"id": 1, "username": "ro", "role": "readonly", "is_active": True}
    api_client.cookies.set("siem_session", create_session_cookie(1, "test-secret"))
    return api_client


def test_readonly_reads_dashboard_but_not_analyst_routes(readonly_client):
    assert readonly_client.get("/api/auth/me").status_code == 200
    assert readonly_client.get("/api/alerts").status_code == 403
    assert readonly_client.post("/block-ip", json=BODY).status_code == 403


@pytest.mark.parametrize(
    "url",
    [
        "/api/ui/alerts?limit=100000",
        "/api/ui/alerts?offset=-1",
        "/api/alerts?limit=0",
        "/api/dashboard-stats?hours=-1",
        "/api/dashboard-stats?hours=100000",
        "/map-data?limit=100000",
    ],
)
def test_query_bounds_return_422(readonly_client, url):
    assert readonly_client.get(url).status_code == 422
