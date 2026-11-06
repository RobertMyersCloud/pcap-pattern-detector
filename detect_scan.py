import sys
from scapy.all import rdpcap, IP, TCP

PCAP_FILE = sys.argv[1]
MIN_PORTS = 5      # distinct destination ports before it counts as a scan
MAX_WINDOW = 60    # seconds; the ports must fall inside one window this long

syns = {}

for pkt in rdpcap(PCAP_FILE):
    if IP in pkt and TCP in pkt and pkt[TCP].flags == "S":
        key = (pkt[IP].src, pkt[IP].dst)
        syns.setdefault(key, []).append((float(pkt.time), pkt[TCP].dport))

for (src, dst), events in syns.items():
    events.sort()
    best_ports = set()
    best_start = best_end = events[0][0]

    for i, (start_time, _) in enumerate(events):
        window_ports = set()
        end_time = start_time
        for t, port in events[i:]:
            if t - start_time > MAX_WINDOW:
                break
            window_ports.add(port)
            end_time = t
        if len(window_ports) > len(best_ports):
            best_ports, best_start, best_end = window_ports, start_time, end_time

    all_ports = {port for _, port in events}
    verdict = "SCAN SUSPECTED" if len(best_ports) >= MIN_PORTS else "not flagged"
    print(f"{verdict}: {src} -> {dst}")
    print(f"  busiest window: {len(best_ports)} distinct ports in {best_end - best_start:.1f} seconds (alert at {MIN_PORTS}+ ports within {MAX_WINDOW}s)")
    print(f"  ports in that window: {sorted(best_ports)}")
    print(f"  whole capture: {len(all_ports)} distinct ports over {events[-1][0] - events[0][0]:.1f} seconds")

print(f"Checked {len(syns)} source/destination pair(s) that sent SYNs")