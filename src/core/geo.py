from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import geoip2.database
from geoip2.errors import AddressNotFoundError


DEFAULT_GEOIP_DB_PATH = (
    os.getenv("GEOIP_DB_PATH")
    or os.getenv("GEO_DB_PATH")
    or "geo/GeoLite2-City.mmdb"
)


@lru_cache(maxsize=1)
def get_geoip_reader() -> geoip2.database.Reader | None:
    db_path = Path(DEFAULT_GEOIP_DB_PATH)
    if not db_path.is_file():
        return None

    try:
        return geoip2.database.Reader(str(db_path))
    except (FileNotFoundError, OSError, ValueError):
        return None


def lookup_ip_location(ip: str) -> dict[str, Any] | None:
    reader = get_geoip_reader()
    if reader is None:
        return None

    try:
        response = reader.city(ip)
    except (AddressNotFoundError, ValueError, OSError):
        return None

    latitude = response.location.latitude
    longitude = response.location.longitude
    if latitude is None or longitude is None:
        return None

    return {
        "country": response.country.name,
        "lat": latitude,
        "lon": longitude,
    }


def enrich_geo(event):
    ip_address = getattr(event, "src_ip", None)
    if not ip_address:
        event.country = None
        event.latitude = None
        event.longitude = None
        return event

    location = lookup_ip_location(ip_address)
    if not location:
        event.country = None
        event.latitude = None
        event.longitude = None
        return event

    event.country = location.get("country")
    event.latitude = location.get("lat")
    event.longitude = location.get("lon")
    return event
