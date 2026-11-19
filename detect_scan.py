import argparse
from collections import Counter

from scapy.all import IP, TCP, PcapReader

MIN_PORTS = 5
MAX_WINDOW = 60


def busiest_window(events):
    """Return the indices of the earliest window with the most distinct ports."""
    counts = Counter()
    end = best_start = best_end = best_count = 0
    for start, (start_time, start_port) in enumerate(events):
        while end < len(events) and events[end][0] - start_time <= MAX_WINDOW:
            counts[events[end][1]] += 1
            end += 1
        if len(counts) > best_count:
            best_start, best_end, best_count = start, end, len(counts)
        counts[start_port] -= 1
        if counts[start_port] == 0:
            del counts[start_port]
    return best_start, best_end


def main():
    parser = argparse.ArgumentParser(description="Find bursts of TCP SYNs to distinct IPv4 ports.")
    parser.add_argument("capture", help="Path to a PCAP or PCAPNG file")
    args = parser.parse_args()
    syns = {}

    with PcapReader(args.capture) as packets:
        for pkt in packets:
            if IP in pkt and TCP in pkt and pkt[TCP].flags & 0x12 == 0x02:
                key = (pkt[IP].src, pkt[IP].dst)
                syns.setdefault(key, []).append((pkt.time, pkt[TCP].dport))

    for (src, dst), events in syns.items():
        events.sort()
        start, end = busiest_window(events)
        best_ports = {events[i][1] for i in range(start, end)}
        best_span = events[end - 1][0] - events[start][0]
        all_ports = {port for _, port in events}
        capture_span = events[-1][0] - events[0][0]
        verdict = "SCAN SUSPECTED" if len(best_ports) >= MIN_PORTS else "not flagged"
        print(f"{verdict}: {src} -> {dst}")
        print(
            f"  busiest window: {len(best_ports)} distinct ports in {best_span:.1f} seconds "
            f"(alert at {MIN_PORTS}+ ports within {MAX_WINDOW}s)"
        )
        print(f"  ports in that window: {sorted(best_ports)}")
        print(f"  whole capture: {len(all_ports)} distinct ports over {capture_span:.1f} seconds")

    print(f"Checked {len(syns)} source/destination pair(s) that sent SYNs")


if __name__ == "__main__":
    main()
