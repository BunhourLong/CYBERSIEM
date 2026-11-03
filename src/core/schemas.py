# siem/core/schemas.py
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class NetworkEvent:
    timestamp: datetime

    # Network identity
    src_ip: str
    dst_ip: str
    protocol: str  # TCP / UDP / ICMP
    src_port: Optional[int]
    dst_port: Optional[int]

    # Traffic metadata
    packet_size: int
    tcp_flags: Optional[str]  # SYN, ACK, SYN-ACK, etc.

    # Geo context (resolved later)
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    # IDS classification
    classification: str = "unknown"
    severity: str = "info"  # info | low | medium | high
    confidence: float = 0.0

    # Correlation helpers
    flow_id: Optional[str] = None
