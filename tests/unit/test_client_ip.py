from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

ROOT = Path(__file__).resolve().parents[2]
NGINX = "172.28.10.10"
TOKEN = "ingest-secret"
SCRIPT = ROOT / "stack" / "nginx" / "real-ip-lines.sh"


def _login(client, xff="1.2.3.4, 198.51.100.7", username="alice"):
    headers = {"X-Forwarded-For": xff} if xff is not None else {}
    return client.post(
        "/login",
        json={"username": username, "password": "wrong"},
        headers=headers,
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
    return TestClient(wrapped, client=("203.0.113.9", 12345))


def test_proxy_chain_uses_rightmost_untrusted_ip(proxied_client, fake_repository):
    from src.api import main

    assert _login(proxied_client).status_code == 401
    assert fake_repository.log_audit_event.call_args.kwargs["source_ip"] == "198.51.100.7"
    assert "198.51.100.7" in main._ip_login_attempts
    assert "1.2.3.4" not in main._ip_login_attempts


def test_proxy_chain_ending_in_nginx_resolves_to_client(proxied_client, fake_repository):
    assert _login(proxied_client, xff=f"1.2.3.4, 198.51.100.7, {NGINX}").status_code == 401
    assert fake_repository.log_audit_event.call_args.kwargs["source_ip"] == "198.51.100.7"


def test_proxy_without_forwarded_header_keeps_nginx_peer(proxied_client, fake_repository):
    assert _login(proxied_client, xff=None).status_code == 401
    assert fake_repository.log_audit_event.call_args.kwargs["source_ip"] == NGINX


def test_spoofed_leftmost_values_share_one_ip_lockout(proxied_client):
    from src.api import main

    for i in range(main._IP_MAX_FAILURES):
        assert _login(proxied_client, xff=f"10.{i}.0.1, 198.51.100.7", username=f"user{i}").status_code == 401
    assert set(main._ip_login_attempts) == {"198.51.100.7"}
    assert _login(proxied_client, xff="10.99.0.1, 198.51.100.7", username="user99").status_code == 429


def test_direct_peer_ignores_forwarded_header(direct_client, fake_repository):
    from src.api import main

    assert _login(direct_client).status_code == 401
    assert fake_repository.log_audit_event.call_args.kwargs["source_ip"] == "203.0.113.9"
    assert "203.0.113.9" in main._ip_login_attempts
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


def test_ingest_valid_ip_beats_spoofed_forwarded_header(api_client, monkeypatch):
    from src.api import main

    monkeypatch.setenv("INGEST_TOKEN", TOKEN)
    monkeypatch.setattr(main.security_engine, "process_event", lambda event: [])
    body = {
        "method": "GET",
        "endpoint": "/",
        "status_code": 200,
        "ip": "198.51.100.20",
        "x_forwarded_for": "10.9.9.9, 1.1.1.1",
    }
    response = api_client.post("/ingest-event", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 202
    assert response.json()["ip"] == "198.51.100.20"
    assert response.json()["ip_source"] == "payload_ip"


def test_ingest_invalid_ip_with_valid_peer_ip_is_422(api_client, monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", TOKEN)
    body = {
        "method": "GET",
        "endpoint": "/",
        "status_code": 200,
        "ip": "not-an-ip",
        "peer_ip": "198.51.100.30",
    }
    response = api_client.post("/ingest-event", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 422


def test_nginx_configs_do_not_hardcode_set_real_ip_from():
    for path in (ROOT / "stack" / "nginx" / "nginx.conf.template", ROOT / "docker" / "nginx" / "nginx.conf"):
        assert "set_real_ip_from" not in path.read_text(encoding="utf-8")


def test_nginx_template_forwards_only_peer_address():
    template = (ROOT / "stack" / "nginx" / "nginx.conf.template").read_text(encoding="utf-8")
    assert "$proxy_add_x_forwarded_for" not in template


@pytest.mark.parametrize(
    "cidrs, code, out",
    [
        (None, 0, ""),
        ("", 0, ""),
        ("127.0.0.1,10.0.0.0/8", 0, "set_real_ip_from 127.0.0.1;\nset_real_ip_from 10.0.0.0/8;\n"),
        ("0.0.0.0/0", 1, ""),
        ("::/0", 1, ""),
        ("0.0.0.0/00", 1, ""),
        ("::/000", 1, ""),
        ("0.0.0.0/1", 1, ""),
        ("128.0.0.0/1", 1, ""),
        ("::/1", 1, ""),
        ("8000::/16", 1, ""),
        ("1.2.3.4/", 1, ""),
        ("1.2.3.4/8/8", 1, ""),
        ("10.0.0.1,,10.0.0.2", 1, ""),
        ("10.0.0.0/8;", 1, ""),
        ("10.0.0.1\n10.0.0.2", 1, ""),
        ("10.0.0.1, 10.0.0.2", 1, ""),
        ("10.0.0.0/8", 0, "set_real_ip_from 10.0.0.0/8;\n"),
        ("10.0.0.0/08", 0, "set_real_ip_from 10.0.0.0/08;\n"),
        ("2001:db8::/32", 0, "set_real_ip_from 2001:db8::/32;\n"),
        ("1.2.3.4", 0, "set_real_ip_from 1.2.3.4;\n"),
        ("10.0.0.0/10", 0, "set_real_ip_from 10.0.0.0/10;\n"),
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


def _compose_value(text, key):
    return re.search(rf"^\s*(?:-\s*)?{key}:\s*(\S+)", text, re.MULTILINE).group(1)


def test_compose_ips_match():
    text = (ROOT / "stack" / "docker-compose.yml").read_text(encoding="utf-8")
    subnet = _compose_value(text, "subnet")
    ipv4_address = _compose_value(text, "ipv4_address")
    forwarded_allow_ips = _compose_value(text, "FORWARDED_ALLOW_IPS")
    assert ipv4_address == forwarded_allow_ips
    assert ipaddress.ip_address(ipv4_address) in ipaddress.ip_network(subnet)

    docker_text = (ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "FORWARDED_ALLOW_IPS" not in docker_text
