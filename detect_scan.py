import sys
from scapy.all import rdpcap, IP, TCP

PCAP_FILE = sys.argv[1]
MIN_PORTS = 5      # distinct destination ports before it counts as a scan
MAX_WINDOW = 60    # seconds; all of those ports must be hit within this time

syns = {}

for pkt in rdpcap(PCAP_FILE):
    if IP in pkt and TCP in pkt and pkt[TCP].flags == "S":
        key = (pkt[IP].src, pkt[IP].dst)
        if key not in syns:
            syns[key] = {"ports": set(), "times": []}
        syns[key]["ports"].add(pkt[TCP].dport)
        syns[key]["times"].append(float(pkt.time))

for (src, dst), data in syns.items():
    port_count = len(data["ports"])
    span = max(data["times"]) - min(data["times"])
    verdict = "SCAN SUSPECTED" if port_count >= MIN_PORTS and span <= MAX_WINDOW else "not flagged"
    print(f"{verdict}: {src} -> {dst}")
    print(f"  {port_count} distinct ports in {span:.1f} seconds (alert at {MIN_PORTS}+ ports within {MAX_WINDOW}s)")
    print(f"  ports: {sorted(data['ports'])}")
print(f"Checked {len(syns)} source/destination pair(s) that sent SYNs")