from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from src.api.auth import create_session_cookie, load_session_secret

REPO_ROOT = Path(__file__).resolve().parents[2]
USER = {"id": 1, "username": "u", "role": "admin", "is_active": True}


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "a" * 31,
        "change_me" * 4,
        "change-me" * 4,
        "changeme" * 5,
        "\ud800" + "a" * 31,
    ],
    ids=["unset", "empty", "whitespace", "31_bytes", "change_me", "change-me", "changeme", "unencodable"],
)
def test_weak_session_secret_is_refused_without_echoing_it(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("SESSION_SECRET", raising=False)
    else:
        monkeypatch.setenv("SESSION_SECRET", value)

    with pytest.raises(RuntimeError) as exc:
        load_session_secret()

    message = str(exc.value)
    assert "SESSION_SECRET" in message
    assert "openssl rand -base64 32" in message
    if value and value.strip() and value.strip() != "SESSION_SECRET":
        assert value.strip() not in message


def test_32_utf8_bytes_is_accepted(monkeypatch):
    secret = "é" * 16  # 32 UTF-8 bytes
    monkeypatch.setenv("SESSION_SECRET", f"  {secret}  ")
    assert load_session_secret() == secret


def test_importing_main_without_a_strong_secret_fails_without_leaking_it():
    leaked = "LeakMe_0123456789"
    env = {**os.environ, "SESSION_SECRET": leaked}
    result = subprocess.run(
        [sys.executable, "-c", "import src.api.main"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert leaked not in result.stdout + result.stderr
    assert "SESSION_SECRET" in result.stderr
    assert "openssl rand -base64 32" in result.stderr


def test_empty_key_forged_cookie_is_rejected(api_client, fake_repository):
    fake_repository.get_user_by_id.return_value = USER
    api_client.cookies.set("siem_session", create_session_cookie(1, ""))
    assert api_client.get("/api/auth/me").status_code == 401


def test_cookie_signed_with_the_real_secret_is_accepted(api_client, fake_repository):
    fake_repository.get_user_by_id.return_value = USER
    api_client.cookies.set("siem_session", create_session_cookie(1, os.environ["SESSION_SECRET"]))
    assert api_client.get("/api/auth/me").status_code == 200


def test_non_ascii_signature_cookie_is_rejected(api_client, fake_repository):
    fake_repository.get_user_by_id.return_value = USER
    api_client.cookies.set("siem_session", "a:b:é")
    assert api_client.get("/api/auth/me").status_code == 401


def test_non_utf8_form_body_is_422(api_client):
    response = api_client.post(
        "/login",
        content=b"username=admin&password=\xff",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"username": "bad\x00user", "password": "x"},
        {"username": "u", "password": "bad\x00pass"},
    ],
    ids=["username", "password"],
)
def test_nul_in_login_fields_is_422(api_client, body):
    assert api_client.post("/login", json=body).status_code == 422


def test_lone_surrogate_in_login_is_422(api_client):
    response = api_client.post(
        "/login",
        content='{"username":"\\ud800","password":"x"}',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
