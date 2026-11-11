import argparse

from scapy.all import IP, TCP, PcapReader


def main():
    parser = argparse.ArgumentParser(description="Print IPv4 TCP packets from a capture.")
    parser.add_argument("capture", help="Path to a PCAP or PCAPNG file")
    args = parser.parse_args()
    count = 0

    with PcapReader(args.capture) as packets:
        for pkt in packets:
            count += 1
            if IP in pkt and TCP in pkt:
                ip, tcp = pkt[IP], pkt[TCP]
                print(f"{pkt.time:.6f}  {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}  {tcp.flags}")

    print(f"Loaded {count} packets")


if __name__ == "__main__":
    main()
