import sys
import statistics
from scapy.all import rdpcap, IP, TCP

PCAP_FILE = sys.argv[1]
MIN_CONNECTIONS = 5   # need at least this many connections to judge the timing
MAX_JITTER = 0.10     # 0.10 = the gaps vary by about 10% or less of the average

conns = {}

for pkt in rdpcap(PCAP_FILE):
    if IP in pkt and TCP in pkt and pkt[TCP].flags == "S":
        key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
        conns.setdefault(key, []).append(float(pkt.time))

for (src, dst, dport), times in conns.items():
    if len(times) < MIN_CONNECTIONS:
        continue
    times.sort()
    gaps = [later - earlier for earlier, later in zip(times, times[1:])]
    mean_gap = statistics.mean(gaps)
    spread = statistics.stdev(gaps)
    jitter = spread / mean_gap
    verdict = "BEACON SUSPECTED" if jitter <= MAX_JITTER else "not flagged"
    print(f"{verdict}: {src} -> {dst}:{dport}")
    print(f"  {len(times)} connections, every {mean_gap:.2f}s on average")
    print(f"  spread {spread:.3f}s, jitter {jitter:.1%} (threshold {MAX_JITTER:.0%})")
print(f"Checked {len(conns)} source/destination/port combination(s) that sent SYNs")