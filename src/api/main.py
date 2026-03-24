from __future__ import annotations

from datetime import datetime, timezone
from math import isfinite
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from src.api.schemas import (
    AlertResponse,
    BlockIPRequest,
    MapPointResponse,
    UpdateAlertStatusRequest,
)
from src.core.geo import lookup_ip_location
from src.core.http_models import DetectionAlert
from src.security_engine.repository import SecurityRepository

app = FastAPI(title="CyberSIEM Alert API", version="0.1.0")
repository = SecurityRepository()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "views"))

DEFAULT_ALERT_LIMIT = 100
DEFAULT_MAP_LIMIT = 200
MAX_MAP_SCAN_LIMIT = 2000
ALERT_STATUSES = ("open", "investigating", "resolved")


def _serialize_alert(alert: dict) -> AlertResponse:
    return AlertResponse.model_validate(alert)


def _list_serialized_alerts(limit: int = DEFAULT_ALERT_LIMIT) -> list[AlertResponse]:
    alerts = repository.list_alerts(limit=limit)
    return [_serialize_alert(alert) for alert in alerts]


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return request.headers.get("hx-request") == "true" or "text/html" in accept


def _render_alerts_partial(request: Request, limit: int = DEFAULT_ALERT_LIMIT) -> HTMLResponse:
    return templates.TemplateResponse(
        "alerts_table.html",
        {
            "request": request,
            "alerts": _list_serialized_alerts(limit=limit),
            "limit": limit,
            "statuses": ALERT_STATUSES,
        },
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
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "alerts": _list_serialized_alerts(limit=limit),
            "limit": limit,
            "statuses": ALERT_STATUSES,
        },
    )


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, limit: int = DEFAULT_ALERT_LIMIT):
    return templates.TemplateResponse(
        "alerts_page.html",
        {
            "request": request,
            "alerts": _list_serialized_alerts(limit=limit),
            "limit": limit,
            "statuses": ALERT_STATUSES,
        },
    )


@app.get("/api/alerts", response_model=list[AlertResponse])
def list_alerts(limit: int = DEFAULT_ALERT_LIMIT):
    return _list_serialized_alerts(limit=limit)


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

        points.append(
            MapPointResponse(
                ip=alert["ip"],
                lat=latitude,
                lon=longitude,
                severity=alert["severity"],
                type=alert["type"],
            )
        )
        seen_points.add(point_key)

        if len(points) >= requested_limit:
            break

    return points


@app.get("/alerts/partial", response_class=HTMLResponse)
def alerts_partial(request: Request, limit: int = DEFAULT_ALERT_LIMIT):
    return _render_alerts_partial(request, limit=limit)


@app.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int):
    alert = repository.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialize_alert(alert)


@app.post("/alerts/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: int,
    request: Request,
    limit: int = DEFAULT_ALERT_LIMIT,
):
    payload = await _get_status_update_payload(request)

    alert = repository.update_alert_status(alert_id, payload.status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if _wants_html(request):
        return _render_alerts_partial(request, limit=limit)

    return _serialize_alert(alert)


@app.post("/block-ip", response_model=AlertResponse)
def block_ip(payload: BlockIPRequest):
    alert = DetectionAlert(
        ip=payload.ip,
        endpoint=payload.endpoint,
        alert_type="manual_block",
        severity="high",
        timestamp=datetime.now(timezone.utc),
        message=payload.reason,
        metadata={"action": "block_ip"},
    )
    alert_id = repository.insert_alert(alert)
    created = repository.get_alert(alert_id)
    if not created:
        raise HTTPException(status_code=500, detail="Unable to persist block request")
    return _serialize_alert(created)
