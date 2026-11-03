from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

ROOT = Path(__file__).resolve().parents[2]
NGINX = "172.28.10.10"
TOKEN = "ingest-secret"
SCRIPT = ROOT / "stack" / "nginx" / "real-ip-lines.sh"


def _login(client):
    return client.post(
        "/login",
        json={"username": "alice", "password": "wrong"},
        headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.7"},
    )


@pytest.fixture
def proxied_client(api_client, fake_repository):
    from src.api import main

    main._login_lockouts.clear()
    main._ip_login_attempts.clear()
    fake_repository.get_user_by_username.return_value = None
    wrapped = ProxyHeadersMiddleware(api_client.app, trusted_hosts=NGINX)
    return TestClient(wrapped, client=(NGINX, 12345))


@pytest.fixture
def direct_client(api_client, fake_repository):
    from src.api import main

    main._login_lockouts.clear()
    main._ip_login_attempts.clear()
    fake_repository.get_user_by_username.return_value = None
    wrapped = ProxyHeadersMiddleware(api_client.app, trusted_hosts=NGINX)
    return TestClient(wrapped, client=("198.51.100.7", 12345))


def test_proxy_chain_uses_rightmost_untrusted_ip(proxied_client, fake_repository):
    from src.api import main

    assert _login(proxied_client).status_code == 401
    assert fake_repository.log_audit_event.call_args.kwargs["source_ip"] == "198.51.100.7"
    assert "198.51.100.7" in main._ip_login_attempts
    assert "1.2.3.4" not in main._ip_login_attempts


def test_direct_peer_ignores_forwarded_header(direct_client, fake_repository):
    from src.api import main

    assert _login(direct_client).status_code == 401
    assert fake_repository.log_audit_event.call_args.kwargs["source_ip"] == "198.51.100.7"
    assert "1.2.3.4" not in main._ip_login_attempts


def test_ingest_with_only_header_fields_is_422(api_client, monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", TOKEN)
    body = {
        "method": "GET",
        "endpoint": "/",
        "status_code": 200,
        "x_forwarded_for": "198.51.100.7",
        "x_real_ip": "198.51.100.8",
        "cf_connecting_ip": "198.51.100.9",
        "peer_ip": "198.51.100.10",
    }
    response = api_client.post("/ingest-event", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 422


@pytest.mark.parametrize(
    "cidrs, code, out",
    [
        (None, 0, ""),
        ("", 0, ""),
        ("127.0.0.1,10.0.0.0/8", 0, "set_real_ip_from 127.0.0.1;\nset_real_ip_from 10.0.0.0/8;\n"),
        ("0.0.0.0/0", 1, ""),
        ("::/0", 1, ""),
        ("10.0.0.0/8;", 1, ""),
    ],
)
def test_real_ip_lines_script(cidrs, code, out):
    env = dict(os.environ)
    env.pop("TRUSTED_PROXY_CIDRS", None)
    if cidrs is not None:
        env["TRUSTED_PROXY_CIDRS"] = cidrs
    result = subprocess.run(  # noqa: S603
        ["/bin/sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == code
    assert result.stdout == out


@pytest.mark.parametrize(
    "compose, subnet, proxy_ip",
    [
        ("docker/docker-compose.yml", "172.28.10.0/24", "172.28.10.10"),
        ("stack/docker-compose.yml", "172.28.20.0/24", "172.28.20.10"),
    ],
)
def test_compose_ips_match(compose, subnet, proxy_ip):
    text = (ROOT / compose).read_text(encoding="utf-8")
    assert f"subnet: {subnet}" in text
    assert f"ipv4_address: {proxy_ip}" in text
    assert f"FORWARDED_ALLOW_IPS: {proxy_ip}" in text
