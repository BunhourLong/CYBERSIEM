from __future__ import annotations

import pytest
from fastapi.routing import APIRoute
from starlette.routing import Mount, Route

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


# The only guarded routes the read-only role may reach. Everything else must answer 403.
READONLY_ALLOWED = {
    ("GET", "/api/auth/me"),
    ("GET", "/api/ui/dashboard"),
    ("GET", "/api/ui/map-points"),
    ("GET", "/api/dashboard-stats"),
    ("GET", "/map-data"),
}
HTML = {"accept": "text/html"}
JSON = {"accept": "*/*"}
# GET /alerts is the Angular route: with Accept text/html it serves the shell only (no data).
HTML_SHELL = {("GET", "/alerts")}


def _call(client, method, path, headers):
    url = path.replace("{alert_id}", "1").replace("{ip}", "203.0.113.7")
    return client.request(method, url, headers=headers, json=BODY if method in ("POST", "PATCH") else None)


@pytest.mark.parametrize("headers", [JSON, HTML], ids=["json", "html"])
def test_every_route_requires_auth_unless_allowlisted(api_client, headers, monkeypatch):
    # With no INGEST_TOKEN the ingest route answers 503; set one so the walk sees the real 401.
    monkeypatch.setenv("INGEST_TOKEN", "walk-token")
    for method, path in _routes():
        if (method, path) in PUBLIC or (headers is HTML and (method, path) in HTML_SHELL):
            continue
        response = _call(api_client, method, path, headers)
        assert response.status_code == 401, f"{method} {path} answered {response.status_code} anonymously"


def test_alerts_html_shell_reads_no_data(api_client, fake_repository):
    _call(api_client, "GET", "/alerts", HTML)
    assert fake_repository.mock_calls == []


def test_only_walked_routes_or_the_static_mount(api_client):
    from src.api.main import app

    for route in app.routes:
        assert isinstance(route, (APIRoute, Route)) or (isinstance(route, Mount) and route.name == "frontend"), route


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


def _guarded_routes():
    for route in api_routes():
        for method in route.methods - {"HEAD", "OPTIONS"}:
            # Ingest uses a shared token, not a session, so the role split does not apply to it.
            if (method, route.path) not in PUBLIC | HTML_SHELL | {("POST", "/ingest-event")}:
                yield method, route


def test_readonly_role_split_matches_the_guards(readonly_client, fake_repository, monkeypatch):
    fake_repository.count_ip_states.return_value = {}
    from src.api import main

    monkeypatch.setattr(main.enforcement_service, "refresh_known_ip_states", lambda **_: None)
    for method, route in _guarded_routes():
        user_level = (method, route.path) in READONLY_ALLOWED
        status = _call(readonly_client, method, route.path, JSON).status_code
        assert (status == 200) if user_level else (status == 403), f"{method} {route.path} gave {status}"


def _login_as(client, repo, role, monkeypatch, active=True):
    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    repo.get_user_by_id.return_value = {"id": 1, "username": "u", "role": role, "is_active": active}
    client.cookies.set("siem_session", create_session_cookie(1, "test-secret"))


def test_admin_routes_403_for_analyst_and_pass_for_admin(api_client, fake_repository, monkeypatch):
    fake_repository.delete_all_alerts.return_value = 3
    _login_as(api_client, fake_repository, "analyst", monkeypatch)
    assert api_client.post("/ip-controls", json=BODY).status_code == 403
    assert api_client.delete("/alerts").status_code == 403
    fake_repository.delete_all_alerts.assert_not_called()
    _login_as(api_client, fake_repository, "admin", monkeypatch)
    assert api_client.delete("/alerts").json() == {"deleted": 3}
    assert api_client.post("/ip-controls", json={}).status_code == 422  # past the guard, body rejected


def test_bad_sessions_get_401_on_every_guarded_route(api_client, fake_repository, monkeypatch):
    good = create_session_cookie(1, "test-secret")
    uid, exp, sig = good.split(":")
    flipped = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    cases = {
        "tampered_sig": (good[: -len(sig)] + flipped, {"id": 1, "username": "u", "role": "admin", "is_active": True}),
        "tampered_uid": (f"2:{exp}:{sig}", {"id": 2, "username": "u", "role": "admin", "is_active": True}),
        "inactive": (good, {"id": 1, "username": "u", "role": "admin", "is_active": False}),
        "missing_user": (good, None),
        "garbage": ("not-a-cookie", {"id": 1, "username": "u", "role": "admin", "is_active": True}),
    }
    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    for name, (cookie, user) in cases.items():
        fake_repository.get_user_by_id.return_value = user
        api_client.cookies.clear()
        api_client.cookies.set("siem_session", cookie)
        for method, path in [("GET", "/api/alerts"), ("GET", "/api/dashboard-stats"), ("DELETE", "/alerts")]:
            assert _call(api_client, method, path, JSON).status_code == 401, f"{name} {method} {path}"


def test_expired_validly_signed_cookie_gets_401(api_client, fake_repository, monkeypatch):
    import hashlib
    import hmac
    import time

    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    fake_repository.get_user_by_id.return_value = {"id": 1, "username": "u", "role": "admin", "is_active": True}
    payload = f"1:{int(time.time()) - 10}"
    sig = hmac.new(b"test-secret", payload.encode(), hashlib.sha256).hexdigest()
    api_client.cookies.set("siem_session", f"{payload}:{sig}")
    assert api_client.get("/api/dashboard-stats").status_code == 401


@pytest.mark.parametrize(
    "value, docs",
    [
        ("true", True),
        ("TRUE", True),
        ("1", False),
        ("yes", False),
        ("false", False),
        ("truee", False),
        (" true", False),
    ],
)
def test_api_docs_flag_only_exact_true_enables_docs(value, docs):
    import os
    import subprocess
    import sys

    code = (
        "from unittest.mock import patch, MagicMock\n"
        "with patch('src.security_engine.repository.SecurityRepository', return_value=MagicMock()):\n"
        "    from src.api.main import app\n"
        "print(sorted(r.path for r in app.routes if r.path in ('/docs','/redoc','/openapi.json')))"
    )
    env = {**os.environ, "API_DOCS_ENABLED": value}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)  # noqa: S603  # fixed argv, no user input
    assert out.returncode == 0, out.stderr[-500:]
    assert ("/docs" in out.stdout) is docs


def test_block_ip_body_validation_runs_after_auth(api_client, fake_repository, monkeypatch):
    for kwargs in ({"content": "{bad", "headers": {"content-type": "application/json"}}, {"json": {"ip": 5}}, {}):
        assert api_client.post("/block-ip", **kwargs).status_code == 401
    _login_as(api_client, fake_repository, "analyst", monkeypatch)
    assert api_client.post("/block-ip", content="{bad", headers={"content-type": "application/json"}).status_code == 422
    assert api_client.post("/block-ip", json={"reason": "x"}).status_code == 422


@pytest.mark.parametrize(
    "path, param, cap",
    [
        ("/api/ui/alerts", "limit", 1000),
        ("/api/ui/alerts", "offset", 1_000_000),
        ("/api/dashboard-stats", "hours", 720),
        ("/map-data", "limit", 1000),
    ],
)
def test_query_cap_edges(api_client, fake_repository, monkeypatch, path, param, cap):
    from src.api import main

    monkeypatch.setattr(main.enforcement_service, "refresh_known_ip_states", lambda **_: None)
    readonly_client = api_client
    _login_as(api_client, fake_repository, "analyst", monkeypatch)
    fake_repository.count_ip_states.return_value = {}
    assert readonly_client.get(f"{path}?{param}={cap + 1}").status_code == 422
    assert readonly_client.get(f"{path}?{param}={cap}").status_code == 200
    low = 0 if param == "offset" else 1
    assert readonly_client.get(f"{path}?{param}={low - 1}").status_code == 422
    assert readonly_client.get(f"{path}?{param}={low}").status_code == 200
