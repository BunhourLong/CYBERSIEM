from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src.api.auth import SESSION_COOKIE, create_session_cookie, hash_password, load_session_secret

REPO_ROOT = Path(__file__).resolve().parents[2]
USER = {"id": 1, "username": "u", "role": "admin", "is_active": True}


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "a" * 31,
        "a" * 31 + "     ",
        "change_me" * 4,
        "CHANGE_ME" * 4,
        "change-me" * 4,
        "changeme" * 5,
        "\udcff" + "a" * 31,
    ],
    ids=[
        "unset",
        "empty",
        "whitespace",
        "31_bytes",
        "31_bytes_padded",
        "change_me",
        "upper_change_me",
        "change-me",
        "changeme",
        "unencodable",
    ],
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
    if value and value.strip():
        assert value.strip() not in message


def test_32_utf8_bytes_is_accepted(monkeypatch):
    secret = "é" * 16  # 32 UTF-8 bytes
    monkeypatch.setenv("SESSION_SECRET", f"  {secret}  ")
    assert load_session_secret() == secret


def test_exactly_32_ascii_bytes_is_accepted(monkeypatch):
    secret = "a" * 32
    monkeypatch.setenv("SESSION_SECRET", secret)
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
    headers = {"cookie": "siem_session=a:b:é".encode("latin-1")}
    assert api_client.get("/api/auth/me", headers=headers).status_code == 401


def test_non_utf8_form_body_is_422(api_client):
    response = api_client.post(
        "/login",
        content=b"username=admin&password=\xff",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 422


def test_non_utf8_json_body_is_422(api_client):
    response = api_client.post(
        "/login",
        content=b'{"username":"\xff","password":"x"}',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422


def test_deeply_nested_json_body_is_422(api_client):
    response = api_client.post(
        "/login",
        content="[" * 100000,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422


def test_percent_encoded_nul_in_form_username_is_422_and_repository_untouched(api_client, fake_repository):
    response = api_client.post(
        "/login",
        content=b"username=ad%00min&password=correct-horse-battery",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 422
    assert fake_repository.mock_calls == []


def test_nul_422_body_does_not_echo_the_password(api_client):
    response = api_client.post("/login", json={"username": "u", "password": "SECRET-PW\x00tail"})
    assert response.status_code == 422
    assert "SECRET-PW" not in response.text


def test_login_cookie_authenticates_me(api_client, fake_repository):
    user = {
        "id": 7,
        "username": "login-user",
        "role": "analyst",
        "is_active": True,
        "password_hash": hash_password("correct-horse-battery"),
    }
    fake_repository.get_user_by_username.return_value = user
    fake_repository.get_user_by_id.return_value = user
    login = api_client.post("/login", json={"username": "login-user", "password": "correct-horse-battery"})
    assert login.status_code == 200
    api_client.cookies.clear()
    api_client.cookies.set(SESSION_COOKIE, login.cookies[SESSION_COOKIE])
    me = api_client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "login-user"


def test_session_key_is_fixed_at_import(api_client, fake_repository, monkeypatch):
    rotated = "rotated-secret-0123456789abcdefghij"
    fake_repository.get_user_by_id.return_value = USER
    monkeypatch.setenv("SESSION_SECRET", rotated)
    api_client.cookies.set("siem_session", create_session_cookie(1, rotated))
    assert api_client.get("/api/auth/me").status_code == 401


def test_correctly_signed_non_integer_expiry_is_rejected(api_client, fake_repository):
    fake_repository.get_user_by_id.return_value = USER
    payload = "1:soon"
    sig = hmac.new(os.environ["SESSION_SECRET"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    api_client.cookies.set("siem_session", f"{payload}:{sig}")
    assert api_client.get("/api/auth/me").status_code == 401


def test_auth_module_imports_without_session_secret():
    env = {key: value for key, value in os.environ.items() if key != "SESSION_SECRET"}
    result = subprocess.run(
        [sys.executable, "-c", "import src.api.auth"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


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
