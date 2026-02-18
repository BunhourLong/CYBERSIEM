from collections import defaultdict, deque
from time import time

WINDOW = 30
history = defaultdict(deque)


def detect_port_scan(events):
    dst_ports = {e.dst_port for e in events if e.dst_port}
    syn_count = sum(1 for e in events if e.tcp_flags == "S")

    if len(dst_ports) >= 10 and syn_count >= 10:
        return "port_scan", "medium", min(1.0, len(dst_ports) / 20)

    return None


def detect_bruteforce(events):
    ports = [e.dst_port for e in events if e.dst_port]
    if not ports:
        return None

    port = max(set(ports), key=ports.count)
    attempts = ports.count(port)

    if attempts >= 20:
        return "brute_force", "high", min(1.0, attempts / 50)

    return None


def classify_event(event):
    now = time()
    buf = history[event.src_ip]
    buf.append((now, event))

    while buf and now - buf[0][0] > WINDOW:
        buf.popleft()

    recent_events = [e for _, e in buf]

    result = detect_bruteforce(recent_events)
    if not result:
        result = detect_port_scan(recent_events)
    if not result:
        result = ("normal", "info", 0.9)

    event.classification, event.severity, event.confidence = result
    return event
