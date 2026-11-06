import sys
import statistics
from scapy.all import rdpcap, IP, TCP

PCAP_FILE = sys.argv[1]
MIN_CONNECTIONS = 5   # need at least this many connections to judge the timing
MAX_JITTER = 0.30     # tuned: jittered beacon scored 16.7%, human browsing 128.2%
RETRY_WINDOW = 5      # seconds; a repeat SYN on the same connection this soon is a retry

conns = {}
last_syn = {}
retries = 0

for pkt in rdpcap(PCAP_FILE):
    if IP in pkt and TCP in pkt and pkt[TCP].flags == "S":
        t = float(pkt.time)
        conn_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        previous = last_syn.get(conn_id)
        last_syn[conn_id] = t
        if previous is not None and t - previous <= RETRY_WINDOW:
            retries += 1
            continue
        key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
        conns.setdefault(key, []).append(t)

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

print(f"Ignored {retries} retried SYN(s) (same connection within {RETRY_WINDOW}s)")
print(f"Checked {len(conns)} source/destination/port combination(s) that sent SYNs")