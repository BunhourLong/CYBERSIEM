from collections import defaultdict, deque
from time import time
from src.core.schemas import NetworkEvent

# Sliding window size (seconds)
WINDOW = 30

# Per-source-IP event history
_history: dict[str, deque] = defaultdict(deque)


# -------------------------
# Detection logic
# -------------------------

def _detect_port_scan(events: list[NetworkEvent]):
    dst_ports = {e.dst_port for e in events if e.dst_port is not None}
    syn_count = sum(1 for e in events if e.tcp_flags == "S")

    if len(dst_ports) >= 10 and syn_count >= 10:
        return {
            "classification": "port_scan",
            "severity": "medium",
            "confidence": min(1.0, len(dst_ports) / 20)
        }

    return None


def _detect_bruteforce(events: list[NetworkEvent]):
    ports = [e.dst_port for e in events if e.dst_port is not None]
    if not ports:
        return None

    most_common_port = max(set(ports), key=ports.count)
    attempts = ports.count(most_common_port)

    if attempts >= 20:
        return {
            "classification": "brute_force",
            "severity": "high",
            "confidence": min(1.0, attempts / 50)
        }

    return None


def _classify_normal():
    return {
        "classification": "normal",
        "severity": "info",
        "confidence": 0.9
    }


# -------------------------
# Public IDS entry point
# -------------------------

def classify_event(event: NetworkEvent) -> NetworkEvent:
    """
    Classify a NetworkEvent using behavioral analysis.
    """

    now = time()
    buffer = _history[event.src_ip]

    # Add current event
    buffer.append((now, event))

    # Remove expired events
    while buffer and now - buffer[0][0] > WINDOW:
        buffer.popleft()

    recent_events = [e for _, e in buffer]

    # Detection order matters
    result = _detect_bruteforce(recent_events)
    if not result:
        result = _detect_port_scan(recent_events)
    if not result:
        result = _classify_normal()

    # Apply classification
    event.classification = result["classification"]
    event.severity = result["severity"]
    event.confidence = result["confidence"]

    return event
