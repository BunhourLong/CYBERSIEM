from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class NetworkEvent:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    packet_size: int
    tcp_flags: Optional[str]

    classification: str = "unknown"
    severity: str = "info"
    confidence: float = 0.0
