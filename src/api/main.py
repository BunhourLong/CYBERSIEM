from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from math import ceil
from math import isfinite
from pathlib import Path
from ipaddress import ip_address
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from src.api.schemas import (
    AlertResponse,
    AlertsPerHour,
    AlertTypeCount,
    BlockedIPResponse,
    BlockIPRequest,
    DashboardStats,
    IngestEventRequest,
    IngestEventResponse,
    IngestedAlertResponse,
    IPControlRequest,
    MapPointResponse,
    SeverityCount,
    TopIPEntry,
    UpdateAlertStatusRequest,
)
from src.core.geo import describe_ip_scope, lookup_ip_location
from src.api.auth import (
    UserSession,
    MIN_PASSWORD_LENGTH,
    SESSION_COOKIE,
    SESSION_TTL,
    create_session_cookie,
    get_current_user,
    hash_password,
    validate_password,
    verify_password,
)
import os
from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.engine import SecurityEngine
from src.security_engine.enforcement import ALERT_STATUSES
from src.security_engine.enforcement_service import EnforcementService
from src.security_engine.intelligence import ASNResolver
from src.security_engine.repository import SecurityRepository

app = FastAPI(title="CyberSIEM Alert API", version="0.1.0")
repository = SecurityRepository()
enforcement_service = EnforcementService(repository=repository)
security_engine = SecurityEngine(
    repository=repository,
    enforcement_service=enforcement_service,
)
asn_resolver = ASNResolver()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "views"))

DEFAULT_ALERT_LIMIT = 100
DEFAULT_MAP_LIMIT = 200
MAX_MAP_SCAN_LIMIT = 2000

# Known-bad SESSION_SECRET values that must be rejected in production
_KNOWN_BAD_SECRETS = frozenset({"change-me", "change-me-in-production", "secret", "dev", ""})

_NO_CACHE_PATHS = frozenset({"/login"})


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if os.getenv("SESSION_SECURE", "").lower() in ("1", "true", "yes"):
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    if request.url.path in _NO_CACHE_PATHS:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response

# Pre-computed dummy hash — verify_password is always called so invalid usernames
# take the same time as valid ones (prevents username enumeration via timing).
_DUMMY_PASSWORD_HASH: str = hash_password("__timing_safety_dummy__")


def _serialize_alert(alert: dict) -> AlertResponse:
    payload = dict(alert)
    payload["ip_scope"] = describe_ip_scope(payload["ip"])

    location = lookup_ip_location(payload["ip"])
    if location:
        payload["country"] = location.get("country")
        payload["country_code"] = location.get("country_code")
        payload["city"] = location.get("city")
        payload["subdivision"] = location.get("subdivision")
        payload["accuracy_radius_km"] = location.get("accuracy_radius_km")
    else:
        payload["country"] = None
        payload["country_code"] = None
        payload["city"] = None
        payload["subdivision"] = None
        payload["accuracy_radius_km"] = None

    payload["reputation_status"] = payload.get("reputation_status") or payload.get("current_state")
    payload["current_state"] = payload.get("current_state") or payload.get("reputation_status")
    payload["current_score"] = float(payload.get("current_score") or 0)
    payload["lifetime_score"] = float(payload.get("lifetime_score") or 0)
    payload["alert_count"] = int(payload.get("alert_count") or payload.get("total_alert_count") or 0)
    payload["malicious_count"] = int(payload.get("malicious_count") or payload.get("malicious_alert_count") or 0)
    payload["block_count"] = int(payload.get("block_count") or 0)
    payload["offense_streak"] = int(payload.get("offense_streak") or 0)
    payload["manual_blocked"] = bool(payload.get("manual_blocked", False))
    payload["blocked_reason"] = payload.get("blocked_reason")
    payload["whitelist"] = bool(payload.get("whitelist", False))
    payload["threshold_reached"] = bool(payload.get("threshold_reached", False))
    payload["reputation_reasons"] = list(payload.get("reputation_reasons") or [])
    payload["block_countdown_seconds"] = _seconds_until(payload.get("blocked_until"))
    payload["cooldown_countdown_seconds"] = _seconds_until(payload.get("cooldown_until"))
    payload["confidence"] = int(payload.get("confidence") or 50)
    return AlertResponse.model_validate(payload)


def _list_serialized_alerts(
    limit: int = DEFAULT_ALERT_LIMIT,
    offset: int = 0,
    filter_type: str | None = None,
    filter_severity: str | None = None,
    filter_status: str | None = None,
    filter_ip: str | None = None,
    blocked_only: bool = False,
) -> list[AlertResponse]:
    alerts = repository.list_alerts(
        limit=limit,
        offset=offset,
        filter_type=filter_type or None,
        filter_severity=filter_severity or None,
        filter_status=filter_status or None,
        filter_ip=filter_ip or None,
        blocked_only=blocked_only,
    )
    return [_serialize_alert(alert) for alert in alerts]


def _serialize_blocked_ip(record: dict) -> BlockedIPResponse:
    payload = dict(record)
    payload["reputation_status"] = payload.get("reputation_status") or payload.get("current_state") or "trusted"
    payload["current_state"] = payload.get("current_state") or payload.get("reputation_status")
    payload["current_score"] = float(payload.get("current_score") or 0)
    payload["lifetime_score"] = float(payload.get("lifetime_score") or 0)
    payload["manual_blocked"] = bool(payload.get("manual_blocked", False))
    payload["whitelist"] = bool(payload.get("whitelist", False))
    payload["block_count"] = int(payload.get("block_count") or 0)
    payload["offense_streak"] = int(payload.get("offense_streak") or 0)
    payload["reputation_reasons"] = list(payload.get("reputation_reasons") or [])
    payload["block_countdown_seconds"] = _seconds_until(payload.get("blocked_until"))
    payload["cooldown_countdown_seconds"] = _seconds_until(payload.get("cooldown_until"))
    return BlockedIPResponse.model_validate(payload)


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return request.headers.get("hx-request") == "true" or "text/html" in accept


def _require_user(request: Request) -> tuple[UserSession | None, object]:
    """Any authenticated user. HTML → redirect /login; API → 401."""
    session = get_current_user(request, repository)
    if session is None:
        if _wants_html(request):
            return None, RedirectResponse(url="/login", status_code=302)
        return None, JSONResponse({"detail": "Authentication required"}, status_code=401)
    return session, None


def _require_analyst(request: Request) -> tuple[UserSession | None, object]:
    """Analyst or admin. HTML → denied.html 403; API → 403."""
    session, err = _require_user(request)
    if err:
        return None, err
    if not session.is_analyst():
        if _wants_html(request):
            return None, templates.TemplateResponse(
                request, "denied.html", {"role": session.role, "required": "analyst"}, status_code=403
            )
        return None, JSONResponse({"detail": "Analyst role required"}, status_code=403)
    return session, None


def _require_admin(request: Request) -> tuple[UserSession | None, object]:
    """Admin only. HTML → denied.html 403; API → 403."""
    session, err = _require_user(request)
    if err:
        return None, err
    if not session.is_admin():
        if _wants_html(request):
            return None, templates.TemplateResponse(
                request, "denied.html", {"role": session.role, "required": "admin"}, status_code=403
            )
        return None, JSONResponse({"detail": "Admin role required"}, status_code=403)
    return session, None


# ---------------------------------------------------------------------------
# Login lockout (in-memory, per-username and per-IP, fixed window)
# ---------------------------------------------------------------------------
_MAX_LOGIN_FAILURES = 5    # per account
_IP_MAX_FAILURES = 20      # per source IP (covers credential-spray across accounts)
_LOCKOUT_SECONDS = 300     # 5 minutes for both windows


# username -> (fail_count, first_failure_timestamp)
_login_lockouts: dict[str, tuple[int, float]] = {}
# ip -> (fail_count, first_failure_timestamp)
_ip_login_attempts: dict[str, tuple[int, float]] = {}


def _remaining(store: dict[str, tuple[int, float]], key: str, max_fails: int) -> int:
    """Seconds remaining in lockout for *key* in *store*. 0 = not locked."""
    entry = store.get(key)
    if not entry or entry[0] < max_fails:
        return 0
    elapsed = time.time() - entry[1]
    if elapsed >= _LOCKOUT_SECONDS:
        store.pop(key, None)
        return 0
    return int(ceil(_LOCKOUT_SECONDS - elapsed))


def _record_failure(store: dict[str, tuple[int, float]], key: str) -> None:
    entry = store.get(key)
    if entry and (time.time() - entry[1]) >= _LOCKOUT_SECONDS:
        entry = None  # window expired — reset
    count = (entry[0] if entry else 0) + 1
    first = entry[1] if entry else time.time()
    store[key] = (count, first)


def _lockout_remaining(username: str) -> int:
    return _remaining(_login_lockouts, username, _MAX_LOGIN_FAILURES)


def _ip_lockout_remaining(ip: str) -> int:
    return _remaining(_ip_login_attempts, ip, _IP_MAX_FAILURES)


def _record_login_failure(username: str, ip: str | None) -> None:
    _record_failure(_login_lockouts, username)
    if ip:
        _record_failure(_ip_login_attempts, ip)


def _clear_lockout(username: str) -> None:
    _login_lockouts.pop(username, None)
    # Intentionally do NOT clear the per-IP counter — one success doesn't mean
    # that IP has stopped spraying other accounts.


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str | None:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


def _audit(actor: str | None, action: str, target: str | None, request: Request) -> None:
    repository.log_audit_event(
        actor=actor or "anonymous",
        action=action,
        target=target,
        source_ip=_client_ip(request),
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@app.post("/login")
async def login(request: Request):
    form_data = await request.form()
    username = str(form_data.get("username", ""))
    password = str(form_data.get("password", ""))
    source_ip = _client_ip(request)

    # Per-IP check first — catches spray attacks targeting many accounts from one IP.
    if source_ip:
        ip_remaining = _ip_lockout_remaining(source_ip)
        if ip_remaining > 0:
            _audit(username or "unknown", "ip_login_blocked", source_ip, request)
            mins = ceil(ip_remaining / 60)
            return templates.TemplateResponse(
                request, "login.html",
                {"error": f"Too many requests from your IP. Try again in {mins} minute{'s' if mins != 1 else ''}."},
                status_code=429,
            )

    # Per-username check.
    lockout_secs = _lockout_remaining(username)
    if lockout_secs > 0:
        _audit(username, "login_blocked", None, request)
        mins = ceil(lockout_secs / 60)
        return templates.TemplateResponse(
            request, "login.html",
            {"error": f"Too many failed attempts. Try again in {mins} minute{'s' if mins != 1 else ''}."},
            status_code=429,
        )

    secret = os.getenv("SESSION_SECRET", "change-me")
    user = repository.get_user_by_username(username)

    # Always call verify_password to prevent username enumeration via timing side-channel.
    phash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(password, phash)

    if not user or not user["is_active"] or not password_ok:
        _record_login_failure(username, source_ip)
        _audit(username, "login_failure", None, request)
        remaining = _lockout_remaining(username)
        if remaining > 0:
            mins = ceil(remaining / 60)
            msg = f"Invalid credentials. Account locked for {mins} minute{'s' if mins != 1 else ''}."
        else:
            entry = _login_lockouts.get(username)
            attempts_left = _MAX_LOGIN_FAILURES - (entry[0] if entry else 0)
            msg = f"Invalid username or password. {attempts_left} attempt{'s' if attempts_left != 1 else ''} remaining before lockout."
        return templates.TemplateResponse(
            request, "login.html", {"error": msg}, status_code=401
        )

    _clear_lockout(username)
    _audit(username, "login_success", None, request)
    response = RedirectResponse(url="/dashboard", status_code=302)
    cookie = create_session_cookie(user["id"], secret)
    secure_flag = os.getenv("SESSION_SECURE", "").lower() in ("1", "true", "yes")
    response.set_cookie(
        SESSION_COOKIE,
        cookie,
        httponly=True,
        samesite="strict",
        secure=secure_flag,
        max_age=SESSION_TTL,
    )
    return response


@app.post("/logout")
def logout(request: Request):
    session = get_current_user(request, repository)
    if session:
        _audit(session.username, "logout", None, request)
    secure_flag = os.getenv("SESSION_SECURE", "").lower() in ("1", "true", "yes")
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        samesite="strict",
        secure=secure_flag,
    )
    return response


def _seconds_until(timestamp: datetime | None) -> int | None:
    if timestamp is None:
        return None

    normalized = _normalize_timestamp(timestamp)
    remaining = (normalized - datetime.now(timezone.utc)).total_seconds()
    if remaining <= 0:
        return 0
    return int(ceil(remaining))


def _refresh_reputation_views(trigger_reason: str) -> None:
    enforcement_service.refresh_known_ip_states(trigger_reason=trigger_reason)


def _alerts_context(
    limit: int,
    offset: int = 0,
    filter_type: str | None = None,
    filter_severity: str | None = None,
    filter_status: str | None = None,
    filter_ip: str | None = None,
    blocked_only: bool = False,
) -> dict:
    alerts = _list_serialized_alerts(
        limit=limit,
        offset=offset,
        filter_type=filter_type,
        filter_severity=filter_severity,
        filter_status=filter_status,
        filter_ip=filter_ip,
        blocked_only=blocked_only,
    )
    blocked_ips = [_serialize_blocked_ip(record) for record in repository.list_blocked_ips()]
    alert_types = repository.get_distinct_alert_types()
    return {
        "alerts": alerts,
        "blocked_ips": blocked_ips,
        "limit": limit,
        "offset": offset,
        "statuses": ALERT_STATUSES,
        "alert_types": alert_types,
        "filter_type": filter_type or "",
        "filter_severity": filter_severity or "",
        "filter_status": filter_status or "",
        "filter_ip": filter_ip or "",
        "blocked_only": blocked_only,
    }


def _dashboard_context(limit: int) -> dict:
    state_counts = repository.count_ip_states()
    top_offenders = [
        _serialize_blocked_ip(record) for record in repository.list_top_ip_reputations(limit=10)
    ]
    recent_transitions = repository.list_recent_reputation_transitions(limit=20)
    alert_type_counts = repository.get_alert_type_counts(hours=24)
    severity_counts = repository.get_severity_counts(hours=24)
    top_ips = repository.get_top_ips_by_alert_count(limit=10, hours=24)
    alerts_per_hour = repository.get_alerts_per_hour(hours=24)
    context = _alerts_context(limit)
    context.update(
        {
            "state_counts": state_counts,
            "top_offenders": top_offenders,
            "recent_transitions": recent_transitions,
            "alert_type_counts": alert_type_counts,
            "severity_counts": severity_counts,
            "top_ips_by_alerts": top_ips,
            "alerts_per_hour": alerts_per_hour,
        }
    )
    return context


def _render_alerts_partial(
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
    offset: int = 0,
    filter_type: str | None = None,
    filter_severity: str | None = None,
    filter_status: str | None = None,
    filter_ip: str | None = None,
    blocked_only: bool = False,
) -> HTMLResponse:
    _refresh_reputation_views(trigger_reason="alerts_partial_refresh")
    return templates.TemplateResponse(
        request,
        "alerts_table.html",
        _alerts_context(
            limit,
            offset=offset,
            filter_type=filter_type,
            filter_severity=filter_severity,
            filter_status=filter_status,
            filter_ip=filter_ip,
            blocked_only=blocked_only,
        ),
    )


def _is_valid_ip(candidate: str | None) -> bool:
    if not candidate or candidate == "-":
        return False

    try:
        ip_address(candidate)
    except ValueError:
        return False
    return True


def _extract_forwarded_ips(raw_value: str | None) -> list[str]:
    if not raw_value or raw_value == "-":
        return []

    return [candidate.strip() for candidate in raw_value.split(",") if _is_valid_ip(candidate.strip())]


def _resolve_ingest_ip(payload: IngestEventRequest) -> tuple[str, str]:
    if _is_valid_ip(payload.ip):
        return payload.ip, payload.ip_source or "payload_ip"

    if _is_valid_ip(payload.cf_connecting_ip):
        return payload.cf_connecting_ip, "cf_connecting_ip"

    forwarded_ips = _extract_forwarded_ips(payload.x_forwarded_for)
    if forwarded_ips:
        return forwarded_ips[0], "x_forwarded_for"

    if _is_valid_ip(payload.x_real_ip):
        return payload.x_real_ip, "x_real_ip"

    if _is_valid_ip(payload.peer_ip):
        return payload.peer_ip, "peer_ip"

    raise HTTPException(status_code=422, detail="No valid client IP was provided for ingestion")


def _normalize_timestamp(timestamp: datetime | None) -> datetime:
    if timestamp is None:
        return datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp


def _build_request_target(payload: IngestEventRequest) -> str:
    if payload.request_target:
        return payload.request_target
    if payload.query:
        return f"{payload.endpoint}?{payload.query}"
    return payload.endpoint


def _build_raw_ingest_record(
    payload: IngestEventRequest,
    resolved_ip: str,
    resolved_source: str,
) -> str:
    if payload.raw_line:
        return payload.raw_line

    return json.dumps(
        {
            "source": "api_ingest",
            "resolved_ip": resolved_ip,
            "resolved_ip_source": resolved_source,
            "peer_ip": payload.peer_ip,
            "x_forwarded_for": payload.x_forwarded_for,
            "x_real_ip": payload.x_real_ip,
            "cf_connecting_ip": payload.cf_connecting_ip,
            "metadata": payload.metadata,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _build_ingest_event(payload: IngestEventRequest) -> HTTPLogEvent:
    resolved_ip, resolved_source = _resolve_ingest_ip(payload)
    return HTTPLogEvent(
        timestamp=_normalize_timestamp(payload.timestamp),
        ip=resolved_ip,
        method=payload.method,
        endpoint=payload.endpoint,
        status_code=payload.status_code,
        user_agent=payload.user_agent,
        request_target=_build_request_target(payload),
        raw_line=_build_raw_ingest_record(payload, resolved_ip, resolved_source),
        query=payload.query,
        referer=payload.referer,
        ip_source=resolved_source,
        peer_ip=payload.peer_ip or "-",
        x_forwarded_for=payload.x_forwarded_for or "-",
        x_real_ip=payload.x_real_ip or "-",
        cf_connecting_ip=payload.cf_connecting_ip or "-",
    )


async def _get_status_update_payload(request: Request) -> UpdateAlertStatusRequest:
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            raw_payload = await request.json()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON payload") from exc
    else:
        body = (await request.body()).decode("utf-8")
        parsed = parse_qs(body, keep_blank_values=True)
        raw_payload = {key: values[-1] for key, values in parsed.items()}

    try:
        return UpdateAlertStatusRequest.model_validate(raw_payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc


async def _get_block_ip_payload(request: Request) -> BlockIPRequest:
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            raw_payload = await request.json()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON payload") from exc
    else:
        body = (await request.body()).decode("utf-8")
        parsed = parse_qs(body, keep_blank_values=True)
        raw_payload = {key: values[-1] for key, values in parsed.items()}

    try:
        return BlockIPRequest.model_validate(raw_payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc


async def _get_ip_control_payload(request: Request) -> IPControlRequest:
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            raw_payload = await request.json()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON payload") from exc
    else:
        body = (await request.body()).decode("utf-8")
        parsed = parse_qs(body, keep_blank_values=True)
        raw_payload = {key: values[-1] for key, values in parsed.items()}

    try:
        return IPControlRequest.model_validate(raw_payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc


@app.on_event("startup")
def startup() -> None:
    enforcement_service.initialize()
    _seed_default_admin()
    _warn_insecure_config()


def _warn_insecure_config() -> None:
    import sys as _sys
    secret = os.getenv("SESSION_SECRET", "change-me")
    if secret in _KNOWN_BAD_SECRETS:
        print(
            "WARNING: SESSION_SECRET is a known-insecure default. "
            "Set SESSION_SECRET to a strong random value before exposing this service.",
            file=_sys.stderr,
        )


def _seed_default_admin() -> None:
    import sys as _sys
    admin_user = os.getenv("ADMIN_USERNAME", "")
    admin_pass = os.getenv("ADMIN_PASSWORD", "")
    if not admin_user or not admin_pass:
        return
    policy_err = validate_password(admin_pass)
    if policy_err:
        print(
            f"WARNING: ADMIN_PASSWORD does not meet policy ({policy_err}) — skipping seed.",
            file=_sys.stderr,
        )
        return
    if not repository.get_user_by_username(admin_user):
        repository.create_user(admin_user, hash_password(admin_pass), role="admin")
        repository.log_audit_event(
            actor="system",
            action="user_created",
            target=admin_user,
            source_ip=None,
        )


@app.get("/")
def root():
    return {
        "status": "CyberSIEM running",
        "services": ["nginx", "security_engine", "api"],
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, limit: int = DEFAULT_ALERT_LIMIT):
    session, err = _require_user(request)
    if err:
        return err
    _refresh_reputation_views(trigger_reason="dashboard_view_refresh")
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {**_dashboard_context(limit), "current_user": session},
    )


@app.get("/alerts")
def alerts_page(
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
    offset: int = 0,
    type: str = "",
    severity: str = "",
    status: str = "",
    ip: str = "",
    blocked_only: bool = False,
):
    session, err = _require_analyst(request)
    if err:
        return err
    _refresh_reputation_views(trigger_reason="alerts_page_refresh")
    ctx = {
        **_alerts_context(
            limit, offset=offset,
            filter_type=type or None,
            filter_severity=severity or None,
            filter_status=status or None,
            filter_ip=ip or None,
            blocked_only=blocked_only,
        ),
        "current_user": session,
    }
    if not _wants_html(request):
        return ctx["alerts"]

    return templates.TemplateResponse(request, "alerts_page.html", ctx)


@app.get("/api/alerts", response_model=list[AlertResponse])
def list_alerts(
    limit: int = DEFAULT_ALERT_LIMIT,
    offset: int = 0,
    type: str = "",
    severity: str = "",
    status: str = "",
    ip: str = "",
    blocked_only: bool = False,
):
    _refresh_reputation_views(trigger_reason="alerts_api_refresh")
    return _list_serialized_alerts(
        limit=limit,
        offset=offset,
        filter_type=type or None,
        filter_severity=severity or None,
        filter_status=status or None,
        filter_ip=ip or None,
        blocked_only=blocked_only,
    )


@app.get("/api/dashboard-stats", response_model=DashboardStats)
def dashboard_stats(hours: int = 24):
    return DashboardStats(
        alert_type_counts=[
            AlertTypeCount(type=row["type"], count=row["count"])
            for row in repository.get_alert_type_counts(hours=hours)
        ],
        severity_counts=[
            SeverityCount(severity=row["severity"], count=row["count"])
            for row in repository.get_severity_counts(hours=hours)
        ],
        top_ips=[
            TopIPEntry(
                ip=row["ip"],
                alert_count=row["alert_count"],
                current_state=row["current_state"],
                current_score=float(row["current_score"]),
            )
            for row in repository.get_top_ips_by_alert_count(limit=10, hours=hours)
        ],
        alerts_per_hour=[
            AlertsPerHour(hour=row["hour"], count=row["count"])
            for row in repository.get_alerts_per_hour(hours=hours)
        ],
        hours_window=hours,
    )


@app.get("/blocked-ips", response_model=list[BlockedIPResponse])
def list_blocked_ips(request: Request):
    _, err = _require_analyst(request)
    if err:
        return err
    _refresh_reputation_views(trigger_reason="blocked_ip_list_refresh")
    return [_serialize_blocked_ip(record) for record in repository.list_blocked_ips()]


def _update_alert_status_response(
    request: Request,
    alert_id: int,
    status: str,
    limit: int,
    filter_type: str | None = None,
    filter_severity: str | None = None,
    filter_status: str | None = None,
    filter_ip: str | None = None,
    blocked_only: bool = False,
):
    alert = enforcement_service.update_alert_status(alert_id, status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if _wants_html(request):
        return _render_alerts_partial(
            request, limit=limit,
            filter_type=filter_type, filter_severity=filter_severity,
            filter_status=filter_status, filter_ip=filter_ip,
            blocked_only=blocked_only,
        )

    return _serialize_alert(alert)


def _manual_block_response(
    request: Request,
    ip: str,
    reason: str,
    limit: int,
    filter_type: str | None = None,
    filter_severity: str | None = None,
    filter_status: str | None = None,
    filter_ip: str | None = None,
    blocked_only: bool = False,
):
    record = enforcement_service.manual_block_ip(ip, reason)
    if _wants_html(request):
        return _render_alerts_partial(
            request, limit=limit,
            filter_type=filter_type, filter_severity=filter_severity,
            filter_status=filter_status, filter_ip=filter_ip,
            blocked_only=blocked_only,
        )
    return _serialize_blocked_ip(record)


def _manual_unblock_response(
    request: Request,
    ip: str,
    limit: int,
    filter_type: str | None = None,
    filter_severity: str | None = None,
    filter_status: str | None = None,
    filter_ip: str | None = None,
    blocked_only: bool = False,
):
    record = enforcement_service.manual_unblock_ip(ip)
    if _wants_html(request):
        return _render_alerts_partial(
            request, limit=limit,
            filter_type=filter_type, filter_severity=filter_severity,
            filter_status=filter_status, filter_ip=filter_ip,
            blocked_only=blocked_only,
        )
    return _serialize_blocked_ip(record)


def _ip_control_response(
    request: Request,
    payload: IPControlRequest,
    limit: int,
    filter_type: str | None = None,
    filter_severity: str | None = None,
    filter_status: str | None = None,
    filter_ip: str | None = None,
    blocked_only: bool = False,
):
    try:
        record = enforcement_service.apply_ip_control(
            payload.ip,
            payload.action,
            reason=payload.reason,
            duration_seconds=payload.duration_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if _wants_html(request):
        return _render_alerts_partial(
            request, limit=limit,
            filter_type=filter_type, filter_severity=filter_severity,
            filter_status=filter_status, filter_ip=filter_ip,
            blocked_only=blocked_only,
        )

    return _serialize_blocked_ip(record)


@app.post("/ingest-event", response_model=IngestEventResponse, status_code=202)
def ingest_event(payload: IngestEventRequest):
    event = _build_ingest_event(payload)
    alerts = security_engine.process_event(event)
    return IngestEventResponse(
        ip=event.ip,
        ip_source=event.ip_source,
        alert_count=len(alerts),
        alerts=[
            IngestedAlertResponse(
                id=alert.id,
                type=alert.alert_type,
                severity=alert.severity,
                message=alert.message,
            )
            for alert in alerts
        ],
    )


@app.post("/blocked-ips", response_model=BlockedIPResponse)
async def block_ip_entry(
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
    type: str = "",
    severity: str = "",
    status: str = "",
    ip_filter: str = "",
    blocked_only: bool = False,
):
    session, err = _require_analyst(request)
    if err:
        return err
    payload = await _get_block_ip_payload(request)
    _audit(session.username, "block_ip", payload.ip, request)
    return _manual_block_response(
        request, payload.ip, payload.reason, limit,
        filter_type=type or None, filter_severity=severity or None,
        filter_status=status or None, filter_ip=ip_filter or None,
        blocked_only=blocked_only,
    )


@app.delete("/blocked-ips/{ip}", response_model=BlockedIPResponse)
def unblock_ip_entry(
    ip: str,
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
    type: str = "",
    severity: str = "",
    status: str = "",
    ip_filter: str = "",
    blocked_only: bool = False,
):
    session, err = _require_analyst(request)
    if err:
        return err
    _audit(session.username, "unblock_ip", ip, request)
    return _manual_unblock_response(
        request, ip, limit,
        filter_type=type or None, filter_severity=severity or None,
        filter_status=status or None, filter_ip=ip_filter or None,
        blocked_only=blocked_only,
    )


@app.post("/ip-controls", response_model=BlockedIPResponse)
async def ip_controls(
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
    type: str = "",
    severity: str = "",
    status: str = "",
    ip_filter: str = "",
    blocked_only: bool = False,
):
    session, err = _require_admin(request)
    if err:
        return err
    payload = await _get_ip_control_payload(request)
    _audit(session.username, f"ip_control:{payload.action}", payload.ip, request)
    return _ip_control_response(
        request, payload, limit,
        filter_type=type or None, filter_severity=severity or None,
        filter_status=status or None, filter_ip=ip_filter or None,
        blocked_only=blocked_only,
    )


@app.get("/map-data", response_model=list[MapPointResponse])
def map_data(limit: int = DEFAULT_MAP_LIMIT):
    requested_limit = max(1, limit)
    scan_limit = min(max(requested_limit * 10, requested_limit), MAX_MAP_SCAN_LIMIT)
    points: list[MapPointResponse] = []
    seen_points: set[tuple[str, float, float, str, str]] = set()

    for alert in repository.list_alert_map_rows(limit=scan_limit):
        location = lookup_ip_location(alert["ip"])
        if not location:
            continue

        latitude = location.get("lat")
        longitude = location.get("lon")
        if latitude is None or longitude is None:
            continue

        latitude = float(latitude)
        longitude = float(longitude)
        if not isfinite(latitude) or not isfinite(longitude):
            continue

        point_key = (
            alert["ip"],
            latitude,
            longitude,
            alert["severity"],
            alert["type"],
        )
        if point_key in seen_points:
            continue

        asn_result = asn_resolver.lookup(alert["ip"])
        points.append(
            MapPointResponse(
                ip=alert["ip"],
                lat=latitude,
                lon=longitude,
                severity=alert["severity"],
                type=alert["type"],
                country=location.get("country"),
                country_code=location.get("country_code"),
                city=location.get("city"),
                subdivision=location.get("subdivision"),
                accuracy_radius_km=location.get("accuracy_radius_km"),
                organization=asn_result.organization,
                is_hosting_provider=asn_result.is_datacenter,
            )
        )
        seen_points.add(point_key)

        if len(points) >= requested_limit:
            break

    return points


@app.get("/alerts/partial", response_class=HTMLResponse)
def alerts_partial(
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
    offset: int = 0,
    type: str = "",
    severity: str = "",
    status: str = "",
    ip: str = "",
    blocked_only: bool = False,
):
    _, err = _require_analyst(request)
    if err:
        return err
    return _render_alerts_partial(
        request, limit=limit, offset=offset,
        filter_type=type or None,
        filter_severity=severity or None,
        filter_status=status or None,
        filter_ip=ip or None,
        blocked_only=blocked_only,
    )


@app.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int):
    _refresh_reputation_views(trigger_reason="alert_detail_refresh")
    alert = repository.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialize_alert(alert)


@app.post("/alerts/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: int,
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
    type: str = "",
    severity: str = "",
    status: str = "",
    ip: str = "",
    blocked_only: bool = False,
):
    _, err = _require_analyst(request)
    if err:
        return err
    payload = await _get_status_update_payload(request)
    return _update_alert_status_response(
        request, alert_id, payload.status, limit,
        filter_type=type or None, filter_severity=severity or None,
        filter_status=status or None, filter_ip=ip or None,
        blocked_only=blocked_only,
    )


@app.patch("/alerts/{alert_id}", response_model=AlertResponse)
async def patch_alert_status(
    alert_id: int,
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
    type: str = "",
    severity: str = "",
    status: str = "",
    ip: str = "",
    blocked_only: bool = False,
):
    _, err = _require_analyst(request)
    if err:
        return err
    payload = await _get_status_update_payload(request)
    return _update_alert_status_response(
        request, alert_id, payload.status, limit,
        filter_type=type or None, filter_severity=severity or None,
        filter_status=status or None, filter_ip=ip or None,
        blocked_only=blocked_only,
    )


@app.post("/block-ip", response_model=AlertResponse)
def block_ip(payload: BlockIPRequest, request: Request):
    session, err = _require_analyst(request)
    if err:
        return err
    _audit(session.username, "block_ip", payload.ip, request)
    alert = DetectionAlert(
        ip=payload.ip,
        endpoint=payload.endpoint,
        alert_type="manual_block",
        severity="high",
        timestamp=datetime.now(timezone.utc),
        message=payload.reason,
        status="safe",
        metadata={"action": "block_ip", "legacy_route": True},
    )
    alert_id = repository.insert_alert(alert)
    enforcement_service.manual_block_ip(payload.ip, payload.reason)
    created = repository.get_alert(alert_id)
    if not created:
        raise HTTPException(status_code=500, detail="Unable to persist block request")
    return _serialize_alert(created)
