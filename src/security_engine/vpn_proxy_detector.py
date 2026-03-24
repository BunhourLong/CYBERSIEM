from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from src.security_engine.intelligence import ASNResolver, TorExitNodeService


@dataclass(slots=True)
class VPNProxyDetectionResult:
    type: str = "vpn_proxy"
    confidence: str = "low"
    reason: str = "No VPN or proxy indicators found"
    source: str = "local"
    is_vpn: bool = False
    is_proxy: bool = False
    organization: str | None = None
    country: str | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["metadata"] = payload["metadata"] or {}
        return payload


class VPNProxyDetector:
    def __init__(
        self,
        asn_resolver: ASNResolver | None = None,
        tor_service: TorExitNodeService | None = None,
    ) -> None:
        self.asn_resolver = asn_resolver or ASNResolver()
        self.tor_service = tor_service or TorExitNodeService()

    def detect_locally(self, ip: str) -> VPNProxyDetectionResult:
        tor_result = self.tor_service.contains(ip)
        if tor_result.is_tor_exit_node:
            return VPNProxyDetectionResult(
                confidence="high",
                reason=tor_result.reason or "Tor exit node detected",
                source="tor",
                is_proxy=True,
                metadata={"tor": asdict(tor_result)},
            )

        asn_result = self.asn_resolver.lookup(ip)
        if asn_result.is_datacenter:
            return VPNProxyDetectionResult(
                confidence="medium",
                reason=asn_result.reason or "Datacenter ASN detected",
                source="asn",
                is_proxy=True,
                organization=asn_result.organization,
                metadata={"asn": asdict(asn_result)},
            )

        return VPNProxyDetectionResult(
            confidence="low",
            reason="Local fallback found no strong VPN/proxy signal",
            metadata={
                "asn": asdict(asn_result),
                "tor": asdict(tor_result),
            },
        )
