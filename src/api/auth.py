from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass

from fastapi import Request

SESSION_COOKIE = "siem_session"
SESSION_TTL = 8 * 3600  # 8 hours — also exported so main.py can set cookie max_age
MIN_PASSWORD_LENGTH = 12
_MIN_SESSION_SECRET_BYTES = 32
_INSECURE_SECRET_MARKERS = ("change_me", "change-me", "changeme")

ROLES = ("readonly", "analyst", "admin")
_ANALYST_AND_ABOVE = frozenset(("analyst", "admin"))


def load_session_secret() -> str:
    """Return a strong SESSION_SECRET, or refuse to start."""
    value = (os.environ.get("SESSION_SECRET") or "").strip()
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        encoded = b""
    if len(encoded) < _MIN_SESSION_SECRET_BYTES or any(marker in value.lower() for marker in _INSECURE_SECRET_MARKERS):
        raise RuntimeError(
            "SESSION_SECRET must be a random value of at least 32 UTF-8 bytes "
            "(generate one with `openssl rand -base64 32`)"
        )
    return value


@dataclass(slots=True)
class UserSession:
    user_id: int
    username: str
    role: str

    def is_analyst(self) -> bool:
        return self.role in _ANALYST_AND_ABOVE

    def is_admin(self) -> bool:
        return self.role == "admin"


def validate_password(password: str) -> str | None:
    """Return an error string if the password fails policy, else None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return None


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}:{dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split(":", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return hmac.compare_digest(dk.hex(), dk_hex)


def create_session_cookie(user_id: int, secret: str) -> str:
    expires = int(time.time()) + SESSION_TTL
    payload = f"{user_id}:{expires}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_session_cookie(cookie: str, secret: str) -> int | None:
    try:
        user_id_str, expires_str, sig = cookie.rsplit(":", 2)
        payload = f"{user_id_str}:{expires_str}"
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig.encode(), expected.encode()):
            return None
        if int(expires_str) < int(time.time()):
            return None
        return int(user_id_str)
    except ValueError:
        return None


def get_current_user(request: Request, repository, secret: str) -> UserSession | None:
    """Verify the session cookie and return the user session, or None if invalid/expired."""
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        return None
    user_id = _verify_session_cookie(cookie, secret)
    if user_id is None:
        return None
    user = repository.get_user_by_id(user_id)
    if not user or not user["is_active"]:
        return None
    return UserSession(user_id=user["id"], username=user["username"], role=user["role"])
