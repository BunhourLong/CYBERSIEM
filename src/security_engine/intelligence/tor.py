from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


TOR_EXIT_ADDRESSES_URL = "https://check.torproject.org/exit-addresses"
DEFAULT_TOR_CACHE_PATH = os.getenv(
    "TOR_EXIT_NODES_CACHE_PATH",
    "/tmp/cybersiem_tor_exit_nodes.txt",
)
DEFAULT_TOR_CACHE_TTL_SECONDS = int(os.getenv("TOR_EXIT_NODES_CACHE_TTL_SECONDS", "21600"))


@dataclass(slots=True)
class TorExitNodeResult:
    ip: str
    is_tor_exit_node: bool
    source: str = "tor"
    reason: str | None = None
    cache_path: str | None = None
    error: str | None = None
    fetched_at: datetime | None = None


class TorExitNodeService:
    def __init__(
        self,
        cache_path: str = DEFAULT_TOR_CACHE_PATH,
        cache_ttl_seconds: int = DEFAULT_TOR_CACHE_TTL_SECONDS,
        source_url: str = TOR_EXIT_ADDRESSES_URL,
    ) -> None:
        self.cache_path = Path(cache_path)
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.source_url = source_url

    def contains(self, ip: str) -> TorExitNodeResult:
        try:
            ip_address(ip)
        except ValueError:
            return TorExitNodeResult(ip=ip, is_tor_exit_node=False, error="invalid_ip")

        nodes, fetched_at, error = self._load_nodes()
        is_match = ip in nodes
        reason = "IP matches cached Tor exit node list" if is_match else None

        return TorExitNodeResult(
            ip=ip,
            is_tor_exit_node=is_match,
            reason=reason,
            cache_path=str(self.cache_path),
            error=error,
            fetched_at=fetched_at,
        )

    def refresh(self) -> TorExitNodeResult:
        nodes, fetched_at, error = self._download_nodes()
        return TorExitNodeResult(
            ip="",
            is_tor_exit_node=False,
            cache_path=str(self.cache_path),
            error=error,
            fetched_at=fetched_at,
            reason=f"Loaded {len(nodes)} Tor exit nodes" if fetched_at else None,
        )

    def _load_nodes(self) -> tuple[set[str], datetime | None, str | None]:
        if self._cache_is_fresh():
            return self._read_cache()

        nodes, fetched_at, error = self._download_nodes()
        if nodes:
            return nodes, fetched_at, error

        cached_nodes, cached_at, _ = self._read_cache()
        fallback_error = error or "tor_list_unavailable"
        return cached_nodes, cached_at, fallback_error

    def _cache_is_fresh(self) -> bool:
        if not self.cache_path.is_file():
            return False
        modified_at = datetime.fromtimestamp(self.cache_path.stat().st_mtime, tz=timezone.utc)
        return datetime.now(timezone.utc) - modified_at <= self.cache_ttl

    def _download_nodes(self) -> tuple[set[str], datetime | None, str | None]:
        try:
            with urlopen(self.source_url, timeout=5) as response:
                payload = response.read().decode("utf-8")
        except (TimeoutError, URLError, OSError):
            return set(), None, "tor_list_download_failed"

        nodes = _parse_exit_addresses(payload)
        fetched_at = datetime.now(timezone.utc)

        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(payload, encoding="utf-8")
        except OSError:
            return nodes, fetched_at, "tor_cache_write_failed"

        return nodes, fetched_at, None

    def _read_cache(self) -> tuple[set[str], datetime | None, str | None]:
        if not self.cache_path.is_file():
            return set(), None, "tor_cache_missing"

        try:
            payload = self.cache_path.read_text(encoding="utf-8")
        except OSError:
            return set(), None, "tor_cache_read_failed"

        modified_at = datetime.fromtimestamp(self.cache_path.stat().st_mtime, tz=timezone.utc)
        return _parse_exit_addresses(payload), modified_at, None


def _parse_exit_addresses(payload: str) -> set[str]:
    nodes: set[str] = set()
    for line in payload.splitlines():
        if not line.startswith("ExitAddress "):
            continue
        parts = line.split()
        if len(parts) >= 2:
            nodes.add(parts[1])
    return nodes
