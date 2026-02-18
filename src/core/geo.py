import geoip2.database
import os

DB_PATH = os.getenv(
    "GEO_DB_PATH",
    "geo/GeoLite2-City.mmdb"
)

reader = geoip2.database.Reader(DB_PATH)


def enrich_geo(event):
    try:
        response = reader.city(event.src_ip)

        event.country = response.country.name
        event.latitude = response.location.latitude
        event.longitude = response.location.longitude

    except Exception:
        event.country = None
        event.latitude = None
        event.longitude = None

    return event
