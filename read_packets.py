from scapy.all import rdpcap, IP, TCP

packets = rdpcap("captures/capture6-recon-scan.pcap")
print(f"Loaded {len(packets)} packets")

for pkt in packets:
    if IP in pkt and TCP in pkt:
        t = float(pkt.time)
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        print(f"{t:.6f}  {src}:{sport} -> {dst}:{dport}  {flags}")