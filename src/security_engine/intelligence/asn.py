from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address
from typing import Final

from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError

DEFAULT_ASN_DB_PATH: Final[str] = os.getenv(
    "GEOIP_ASN_DB_PATH",
    "data/GeoLite2-ASN.mmdb",
)

KNOWN_DATACENTER_KEYWORDS: Final[dict[str, tuple[str, ...]]] = {
    "aws": ("amazon", "aws"),
    "cloudflare": ("cloudflare",),
    "google_cloud": ("google", "google cloud"),
    "azure": ("microsoft", "azure"),
    "digitalocean": ("digitalocean",),
    "ovh": ("ovh",),
    "hetzner": ("hetzner",),
}


@dataclass(slots=True)
class ASNDetectionResult:
    ip: str
    asn: int | None = None
    organization: str | None = None
    provider: str | None = None
    is_datacenter: bool = False
    reason: str | None = None
    source: str = "asn"
    error: str | None = None


class ASNResolver:
    def __init__(self, database_path: str = DEFAULT_ASN_DB_PATH) -> None:
        self.database_path = database_path

    @property
    def is_available(self) -> bool:
        return os.path.isfile(self.database_path)

    @lru_cache(maxsize=1)  # noqa: B019
    def _reader(self) -> Reader | None:
        if not self.is_available:
            return None
        return Reader(self.database_path)

    def lookup(self, ip: str) -> ASNDetectionResult:
        try:
            ip_address(ip)
        except ValueError:
            return ASNDetectionResult(ip=ip, error="invalid_ip")

        reader = self._reader()
        if reader is None:
            return ASNDetectionResult(ip=ip, error="asn_database_unavailable")

        try:
            response = reader.asn(ip)
        except AddressNotFoundError:
            return ASNDetectionResult(ip=ip, error="asn_not_found")

        organization = (response.autonomous_system_organization or "").strip()
        normalized_org = organization.casefold()
        provider = _match_provider(normalized_org)
        is_datacenter = provider is not None
        reason = f"ASN {response.autonomous_system_number} belongs to {organization}" if organization else None

        return ASNDetectionResult(
            ip=ip,
            asn=response.autonomous_system_number,
            organization=organization or None,
            provider=provider,
            is_datacenter=is_datacenter,
            reason=reason,
        )


def _match_provider(organization: str) -> str | None:
    for provider, keywords in KNOWN_DATACENTER_KEYWORDS.items():
        if any(keyword in organization for keyword in keywords):
            return provider
    return None
