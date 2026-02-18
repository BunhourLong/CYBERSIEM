from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
from src.core.schemas import NetworkEvent


def packet_to_event(packet):
    if IP not in packet:
        return None

    protocol = "OTHER"
    src_port = dst_port = tcp_flags = None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return NetworkEvent(
        timestamp=datetime.utcnow(),
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        packet_size=len(packet),
        tcp_flags=tcp_flags
    )
