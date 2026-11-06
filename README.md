# PCAP Pattern Detector

Two small Python detectors that read a packet capture and flag two behaviors: **port scanning** and **beacon-like periodic connections**. I wrote them to find in code what I had first found by hand in my [packet analysis lab](https://github.com/RobertMyersCloud/packet-analysis-lab), then tested them on fresh traffic from my own lab range, including traffic built to get past them.

## At a Glance
- **What I did:** Wrote a scan detector and a beacon detector in Python with scapy, generated new test traffic between two lab hosts, and recorded what each detector caught, missed, and got wrong.
- **What it shows:** Turning a manual packet-analysis finding into a repeatable detection rule, then testing that rule against traffic it wasn't built around and tuning it from measured results.
- **What I found:** The first scan detector could be hidden by a single later connection, because it measured a host's whole time in the capture instead of a time window. The beacon detector counted retried SYNs as new connections. Both are fixed, and each fix was checked against the earlier results so nothing that worked before broke.
- **Why it matters for detection and response:** A rule that has only been tested on the traffic it was written for hasn't really been tested. Most of the useful findings here came from the tests built to make the detectors fail.

---

## How the Detectors Work

Both detectors look only at TCP SYN packets, the first packet of a connection attempt. A scan and a beacon are both defined by what a host *tries* to connect to, not by how the other side answers.

### Scan detector (`detect_scan.py`)

A scan is one source sending connection attempts to many different ports on one target in a short time.

- Groups SYNs by source and destination.
- Treats every SYN as the possible start of a 60-second window and finds the window with the most distinct destination ports.
- Alerts when that busiest window has **5 or more distinct ports**.

For every pair it prints the busiest window and the whole-capture totals, flagged or not, so a miss shows which condition failed.

### Beacon detector (`detect_beacon.py`)

A beacon is one host connecting to the same service over and over at a steady interval.

- Groups connections by source, destination, and destination port.
- Needs at least 5 connections to judge timing.
- Measures the gaps between connections, then divides the spread of the gaps (standard deviation) by the average gap. I call that ratio **jitter**. Dividing by the average makes a 1-second wobble on a 10-second beacon score differently from a 1-second wobble on an hourly one.
- Alerts when jitter is **30% or less**.
- A repeat SYN on the same connection (same source IP and port, same destination IP and port) within 5 seconds counts as a retry, not a new connection. The number of ignored retries is printed every run.

It prints the measurement for every stream it checks, flagged or not.

## Usage

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

python detect_scan.py path\to\capture.pcap
python detect_beacon.py path\to\capture.pcap
```

`read_packets.py` prints every TCP packet in a capture in a tcpdump-style one-line format. It was the first step and is useful for checking a capture by eye.

---

## Test Environment

| Role | Host | Address |
|---|---|---|
| Traffic source | Victus (Windows 11) | `10.10.20.102` |
| Target and capture point | ENVY (Fedora) | `10.10.30.10`, VLAN 30 enclave |

ENVY is the protected enclave host from [Prove-It NET-008](https://github.com/RobertMyersCloud/prove-it/tree/main/01-networking/NET-008-protected-systems-enclave). Its address changed after that project: it now has a DHCP reservation at `10.10.30.10`.

Its firewall only allows SSH from Victus, so the tests needed a temporary opening:

- I recorded the firewall's state first (`firewall-cmd --list-all`): no open ports, one rich rule allowing TCP 22 from `10.10.20.102/32`.
- I added one **runtime-only** rule (no `--permanent`) allowing TCP 65002 from `10.10.20.102/32` only.
- The test server was Python's built-in `http.server`, bound to `10.10.30.10`, serving a folder holding one test page and nothing else, running as my normal user.
- After testing I stopped the server and removed the rule. `--list-all` matched the starting state line for line. A request from Victus to port 65002 then timed out after 5 seconds.

Captures were taken on ENVY with tcpdump, filtered to Victus's traffic with SSH excluded:

```bash
sudo tcpdump -i enp0s20f0u3u3c2 -nn -Z robert-myers -w ~/pcap-tests/<test>.pcap 'host 10.10.20.102 and not port 22'
```

Excluding port 22 kept my own SSH sessions out of the captures. It also means a scan probe to port 22 wouldn't be captured, so the generated scans used 8080 in its place.

The two original captures (`capture6-recon-scan`, `capture7-periodic-traffic`) come from the packet analysis lab, from when ENVY was at `10.10.30.100`.

### Test traffic

| Test | How it was generated (from Victus) |
|---|---|
| 1. Steady beacon | 12 HTTP requests, 10 seconds apart |
| 2. Jittered beacon | 12 HTTP requests, each wait random between 7 and 13 seconds (±30%) |
| 3. Slow scan | TCP connection attempts to 11 ports with a 10-second pause between them (about 11.1 seconds apart in the capture) |
| 3b. Fast scan, then a request | The same 11 ports with a 0.5-second pause between them, then a 90-second pause, then one HTTP request |
| 4. Human browsing | Refreshing the test page by hand in a browser at irregular moments |

Raw captures are not published. They contain MAC addresses and full lab network detail.

---

## Results

Final settings: scan alert at 5+ ports within 60 seconds; beacon alert at 30% jitter or less.

| Capture | Scan detector | Beacon detector |
|---|---|---|
| Original fast scan (11 ports) | ✅ Flagged: 11 ports in 5.1 s | Not flagged (1–2 SYNs per port); 2 retries ignored |
| Original periodic traffic | Not flagged: 1 port | ✅ Flagged: 6 connections, every 10.04 s, jitter 0.1% |
| 1. Steady beacon | Not flagged: 1 port | ✅ Flagged: 12 connections, every 10.05 s, jitter 0.1% |
| 2. Jittered beacon | — | ✅ Flagged: 12 connections, every 10.81 s, jitter 16.7% |
| 3. Slow scan | ✅ Flagged: 6 ports in 56.1 s | — |
| 3b. Fast scan, then a request | ✅ Flagged: 11 ports in 16.2 s | — |
| 4. Human browsing | Not flagged: 1 port | Not flagged: 37 connections, jitter 128.2% |

Test 1's capture was 120 packets with 0 dropped by the kernel, 10 packets per connection. The detector counted all 12 connections and none of the earlier path-check request, which happened before the capture started.

### Before tuning

At the starting threshold of 10%, Test 2's jittered beacon (16.7%) was missed. That was the expected result: real command-and-control tools randomize their check-ins for exactly this reason. I didn't pick a new threshold until I had measured normal traffic (Test 4, 128.2%). 30% catches the jittered beacon and is still more than four times below the human browsing score.

| Traffic | Jitter | At 10% | At 30% |
|---|---|---|---|
| Steady beacon | 0.1% | Flagged | Flagged |
| Jittered beacon (±30%) | 16.7% | **Missed** | Flagged |
| Human browsing | 128.2% | Not flagged | Not flagged |

---

## Findings

### Finding 1: one later connection hid a fast scan

**Expected:** a fast scan is flagged no matter what else the host does afterward.
**Observed:** Test 3b, a fast 11-port scan followed 90 seconds later by one normal HTTP request, was **not flagged**. The detector reported 12 distinct ports in 108.8 seconds.
**Root cause:** the original rule measured `max(times) - min(times)`, the time from a host's first SYN to its last in the whole capture. That's not a 60-second window. One later connection stretched it past 60 seconds, and the scan disappeared. Any scan inside a long capture would have disappeared the same way.
**Fix:** a sliding window. Every SYN is treated as a possible window start, and the busiest 60-second window decides the alert.
**Validation:** Test 3b is now flagged with 11 ports in 16.2 seconds, and that window doesn't include the later request's port (65002). The original fast scan is still flagged and the beacon captures are still not.

A side effect: Test 3's slow scan is now flagged, because probes about 11.1 seconds apart put 6 ports inside one window. That doesn't mean slow scans in general are caught. 5 ports within 60 seconds needs a probe at least every 15 seconds:

| Seconds between probes | Ports in the busiest 60 s window | Flagged |
|---|---|---|
| 0.5 (original scan) | all 11 | Yes |
| 11.1 (Test 3) | 6 | Yes |
| 15 | 5 | Yes, just |
| 20 | 4 | No |

### Finding 2: retried SYNs were counted as new connections

**Expected:** each connection counts once.
**Observed:** the first run of Test 4 reported 360 connections, an average of one every 0.53 seconds, far more than a person refreshing a page could produce. Counting by source port gave 360 SYNs from only 71 source ports.
**Investigated:** I printed the packets for the source port that sent the most SYNs. ENVY answered every SYN immediately with a reset (`RA`), and Windows retried every 0.5 seconds, five times:

```text
1793971378.804  10.10.20.102:49771 -> 10.10.30.10:65002  S
1793971378.804  10.10.30.10:65002 -> 10.10.20.102:49771  RA
1793971379.317  10.10.20.102:49771 -> 10.10.30.10:65002  S
1793971379.317  10.10.30.10:65002 -> 10.10.20.102:49771  RA
1793971379.832  10.10.20.102:49771 -> 10.10.30.10:65002  S
```

A reset in answer to a SYN means nothing was listening: **the test server wasn't running during that run**, so it wasn't a valid browsing test. The same source port came back about 35 seconds later for a second burst.

**Root cause (detector):** every SYN was counted as a new connection, so retries inflated the count and added false short gaps to the jitter.
**Fix:** a repeat SYN with the same source IP, source port, destination IP, and destination port within 5 seconds of the previous one is a retry and isn't counted. It is time-based, not "one per source port," because the same port can be reused for a genuinely new connection. Port 49771 did that after 35 seconds, and the valid Test 4 run had 37 accepted connections from only 35 source ports.
**Validation:** Tests 1, 2, and 4 gave the same numbers as before the fix with 0 retries ignored. The original fast scan reports exactly 2 retries ignored: the second SYNs to ports 3389 and 65000 that I had documented by hand in the packet analysis lab.

**Test 4 was rerun** with the server confirmed up: 37 SYNs, 37 SYN-ACKs from ENVY, 0 resets. That run is the one in the results table. I saved the rerun under the same filename, which overwrote the invalid capture both on ENVY and locally. The packet listing above is the remaining record of it. Since then, every run gets its own filename.

---

## Limitations

- **Small sample.** The threshold was tuned on one capture of each kind, in my lab, not on real network traffic.
- **Legitimate scheduled traffic will be flagged.** Update checks, health monitors, and polling agents really are periodic. A beacon alert is a lead for an analyst, not a verdict.
- **Beacons that change destination or port** are split into separate streams and may never reach 5 connections in one.
- **Scans slower than one probe per 15 seconds** are not flagged, and neither are scans spread across many source addresses, since each source/target pair is judged on its own.
- **TCP over IPv4 only.** UDP, ICMP, and IPv6 are ignored.
- **The sliding window compares every SYN with the ones after it.** That's fine for lab captures of a few hundred SYNs but would be slow on hours of traffic.
- **Reads saved captures only**, not live traffic.

## What I'd Improve Next

- A faster sliding window that moves the start and end forward together instead of rescanning from each SYN.
- One command that runs both detectors and takes the thresholds as options instead of constants in the code.
- Tests that run the detectors against the saved captures automatically, so a code change that alters a result is caught right away.
- Testing against longer, mixed captures with several hosts and real background traffic.

## Files

| File | Purpose |
|---|---|
| `detect_scan.py` | Scan detector |
| `detect_beacon.py` | Beacon detector |
| `read_packets.py` | Prints TCP packets from a capture, one line each |
| `requirements.txt` | Pinned dependency: scapy 2.8.0, the version the results were produced with |
