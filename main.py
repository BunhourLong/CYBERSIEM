from scapy.all import sniff
from src.collectors.local.scapy_sniffer import packet_to_event
from src.ids.engine import classify_event
from src.storage.mongo import save_event
from src.core.geo import enrich_geo


def handle_packet(packet):
    event = packet_to_event(packet)
    if not event:
        return

    event = classify_event(event)
    event = enrich_geo(event)   # 🔥 THIS WAS MISSING

    save_event(event)

    print(
        f"[{event.classification.upper()}] "
        f"{event.src_ip} ({event.country}) → "
        f"{event.dst_ip}"
    )


def main():
    print("Starting Sentinel IDS...")
    sniff(prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
