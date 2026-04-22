from __future__ import annotations

import os
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import geoip2.database
from geoip2.errors import AddressNotFoundError


DEFAULT_GEOIP_DB_PATHS = tuple(
    path
    for path in (
        os.getenv("GEOIP_DB_PATH"),
        os.getenv("GEO_DB_PATH"),
        "data/GeoLite2-City.mmdb",
        "geo/GeoLite2-City.mmdb",
        "/data/GeoLite2-City.mmdb",
    )
    if path
)


def _log_geo(message: str) -> None:
    print(f"[geo] {message}", flush=True)


@lru_cache(maxsize=1)
def get_geoip_reader() -> geoip2.database.Reader | None:
    for candidate in DEFAULT_GEOIP_DB_PATHS:
        db_path = Path(candidate)
        if not db_path.is_file():
            continue

        try:
            _log_geo(f"Initialized GeoLite reader from {db_path}")
            return geoip2.database.Reader(str(db_path))
        except (FileNotFoundError, OSError, ValueError):
            continue

    _log_geo(
        "GeoLite reader unavailable; checked paths="
        + ", ".join(str(Path(candidate)) for candidate in DEFAULT_GEOIP_DB_PATHS)
    )
    return None


def describe_ip_scope(ip: str) -> str:
    try:
        parsed_ip = ip_address(ip)
    except ValueError:
        return "invalid"

    if parsed_ip.is_loopback:
        return "loopback"
    if parsed_ip.is_private:
        return "private"
    if parsed_ip.is_link_local:
        return "link_local"
    if parsed_ip.is_multicast:
        return "multicast"
    if parsed_ip.is_reserved:
        return "reserved"
    if parsed_ip.is_unspecified:
        return "unspecified"
    if parsed_ip.is_global:
        return "public"
    return "non_public"


def is_public_ip(ip: str) -> bool:
    return describe_ip_scope(ip) == "public"


def lookup_ip_location(ip: str) -> dict[str, Any] | None:
    scope = describe_ip_scope(ip)
    if scope != "public":
        _log_geo(f"Skipping GeoLite lookup for ip={ip} reason={scope}")
        return None

    reader = get_geoip_reader()
    if reader is None:
        _log_geo(f"GeoLite lookup failed for ip={ip} reason=reader_unavailable")
        return None

    try:
        response = reader.city(ip)
    except AddressNotFoundError:
        _log_geo(f"GeoLite lookup failed for ip={ip} reason=address_not_found")
        return None
    except (ValueError, OSError) as exc:
        _log_geo(f"GeoLite lookup failed for ip={ip} reason={type(exc).__name__}")
        return None

    latitude = response.location.latitude
    longitude = response.location.longitude
    if latitude is None or longitude is None:
        _log_geo(f"GeoLite lookup failed for ip={ip} reason=missing_coordinates")
        return None

    _log_geo(
        "GeoLite lookup succeeded for "
        f"ip={ip} country={response.country.name!r} city={response.city.name!r}"
    )
    return {
        "country": response.country.name,
        "country_code": response.country.iso_code,
        "city": response.city.name,
        "subdivision": response.subdivisions.most_specific.name,
        "lat": latitude,
        "lon": longitude,
        "accuracy_radius_km": response.location.accuracy_radius,
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
