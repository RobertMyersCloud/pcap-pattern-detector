import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap, wrpcapng

ROOT = Path(__file__).resolve().parents[1]
CLIENT = "192.0.2.10"
SERVER = "198.51.100.20"


def packet(time, *, sport=50000, dport=443, seq=100, flags="S", src=CLIENT, dst=SERVER):
    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src=src, dst=dst
    ) / TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    frame.time = Decimal(str(time))
    return frame


class DetectorTests(unittest.TestCase):
    def run_capture(self, script, frames, *, pcapng=False):
        with tempfile.TemporaryDirectory() as temp:
            capture = Path(temp) / ("sample capture.pcapng" if pcapng else "sample capture.pcap")
            writer = wrpcapng if pcapng else wrpcap
            writer(str(capture), frames)
            result = subprocess.run(
                [sys.executable, str(ROOT / script), str(capture)],
                cwd=temp,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_scan_includes_boundary_and_ecn_but_ignores_syn_ack(self):
        frames = [packet(t, dport=p) for t, p in zip((0, 10, 20, 30), range(80, 84))]
        frames += [
            packet(60, dport=84, flags="SEC"),
            packet(61, dport=86, flags="SA", src=SERVER, dst=CLIENT),
            packet(120, dport=85),
        ]
        output = self.run_capture("detect_scan.py", frames)
        self.assertIn(f"SCAN SUSPECTED: {CLIENT} -> {SERVER}", output)
        self.assertIn("5 distinct ports in 60.0 seconds", output)
        self.assertIn("ports in that window: [80, 81, 82, 83, 84]", output)
        self.assertIn("whole capture: 6 distinct ports", output)
        self.assertIn("Checked 1 source/destination pair(s)", output)

    def test_scan_does_not_count_duplicates_or_merge_targets(self):
        frames = [packet(t, dport=p) for t, p in zip((0, 10, 20, 30), range(80, 84))]
        frames += [
            packet(0, dport=80),
            packet(60.000001, dport=84),
            packet(20, dport=85, dst="198.51.100.21"),
        ]
        output = self.run_capture("detect_scan.py", frames)
        self.assertNotIn("SCAN SUSPECTED", output)
        self.assertIn("busiest window: 4 distinct ports", output)
        self.assertIn("Checked 2 source/destination pair(s)", output)

    def test_beacon_handles_long_retries_and_reused_ports(self):
        frames = [packet(t, seq=100 + i, flags="SEC") for i, t in enumerate(range(0, 10, 2))]
        frames += [packet(t) for t in (16, 32, 64)]
        frames += [packet(9, seq=999, flags="SA")]
        output = self.run_capture("detect_beacon.py", frames)
        self.assertIn(f"BEACON SUSPECTED: {CLIENT} -> {SERVER}:443", output)
        self.assertIn("5 connections, every 2.00s on average", output)
        self.assertIn("Ignored 3 retried SYN(s)", output)

    def test_beacon_skips_zero_span_and_rejects_irregular_traffic(self):
        frames = [packet(1, sport=50000 + i) for i in range(5)]
        frames += [
            packet(t, dport=80, sport=50000 + i)
            for i, t in enumerate((0, 1, 2, 3, 100))
        ]
        output = self.run_capture("detect_beacon.py", frames)
        self.assertIn(f"not scored: {CLIENT} -> {SERVER}:443", output)
        self.assertIn(f"not flagged: {CLIENT} -> {SERVER}:80", output)
        self.assertNotIn("BEACON SUSPECTED", output)

    def test_packet_reader_accepts_pcapng_path(self):
        output = self.run_capture("read_packets.py", [packet(1)], pcapng=True)
        self.assertIn(f"1.000000  {CLIENT}:50000 -> {SERVER}:443  S", output)
        self.assertIn("Loaded 1 packets", output)


if __name__ == "__main__":
    unittest.main()
