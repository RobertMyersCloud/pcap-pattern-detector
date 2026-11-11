import argparse
import statistics

from scapy.all import IP, TCP, PcapReader

MIN_CONNECTIONS = 5
MAX_JITTER = 0.30


def main():
    parser = argparse.ArgumentParser(description="Find periodic TCP connection attempts over IPv4.")
    parser.add_argument("capture", help="Path to a PCAP or PCAPNG file")
    args = parser.parse_args()
    conns = {}
    retries = 0

    with PcapReader(args.capture) as packets:
        for pkt in packets:
            if IP not in pkt or TCP not in pkt or pkt[TCP].flags & 0x12 != 0x02:
                continue
            ip, tcp = pkt[IP], pkt[TCP]
            key = (ip.src, ip.dst, tcp.dport)
            attempts = conns.setdefault(key, {})
            # TCP retransmits the original SYN with the same initial sequence number.
            attempt = (tcp.sport, tcp.seq)
            if attempt in attempts:
                retries += 1
                attempts[attempt] = min(attempts[attempt], pkt.time)
            else:
                attempts[attempt] = pkt.time

    for (src, dst, dport), attempts in conns.items():
        if len(attempts) < MIN_CONNECTIONS:
            continue
        times = sorted(attempts.values())
        gaps = [float(later - earlier) for earlier, later in zip(times, times[1:])]
        mean_gap = statistics.mean(gaps)
        if mean_gap <= 0:
            print(f"not scored: {src} -> {dst}:{dport}")
            print(f"  {len(times)} connection attempts share the same timestamp")
            continue
        spread = statistics.stdev(gaps)
        jitter = spread / mean_gap
        verdict = "BEACON SUSPECTED" if jitter <= MAX_JITTER else "not flagged"
        print(f"{verdict}: {src} -> {dst}:{dport}")
        print(f"  {len(times)} connections, every {mean_gap:.2f}s on average")
        print(f"  spread {spread:.3f}s, jitter {jitter:.1%} (threshold {MAX_JITTER:.0%})")

    print(f"Ignored {retries} retried SYN(s) (matching endpoints, ports, and initial sequence)")
    print(f"Checked {len(conns)} source/destination/port combination(s) that sent SYNs")


if __name__ == "__main__":
    main()
