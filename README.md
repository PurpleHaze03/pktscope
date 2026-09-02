# pktscope

**A live network packet analyzer with built-in intrusion detection, in modern C++.**

pktscope captures traffic from a live interface or a `.pcap` file, dissects it
layer by layer (Ethernet → ARP / IPv4 / IPv6 → TCP / UDP / ICMP → DNS), tracks
conversations as flows, and runs a set of stateful security detections over the
stream — port scans, stealth scans, ARP cache poisoning, SYN floods, and DNS
tunneling. Live traffic is shown in an ncurses dashboard; files produce a text
or JSON report.

Design goals: a bounds-checked, fuzz-resilient parser (the tool must not itself
be exploitable by the hostile input it inspects), a clean layered architecture,
and a full test suite including replay of crafted attack captures.

```
$ pktscope -r port_scan.pcap
========================================================
 pktscope report -- port_scan.pcap
========================================================
Packets     : 40  (0 malformed)
Flows       : 39
Protocol breakdown:
  IPv4          40  100.0%  ##############################
  TCP           40  100.0%  ##############################
Top talkers (by bytes):
  192.168.1.66:44444 -> 192.168.1.10:22 TCP    108 B    2 pkt  SYN_SENT
  ...
Security alerts (1):
  [CRIT] port-scan    192.168.1.66 probed 15 ports in 5s (SYN scan)
========================================================
```

---

## Features

**Protocol dissection** — Ethernet (incl. 802.1Q VLAN), ARP, IPv4, IPv6,
TCP (full flag decode), UDP, ICMP/ICMPv6, and DNS query parsing. Handles the
Ethernet, raw-IP, and loopback (`DLT_NULL`) link types. Every parser reads
through a single bounds-checked `ByteReader`, so a truncated or malformed
packet yields a clean "malformed" result — never a crash or out-of-bounds read.

**Flow tracking** — packets are aggregated into bidirectional 5-tuple
conversations with byte/packet counters and a simplified TCP state machine
(`SYN_SENT → SYN_ACK → ESTABLISHED → CLOSING → CLOSED`), driving a top-talkers
view.

**Intrusion detection** — five stateful detectors, all using packet capture
timestamps (not wall-clock) so results are identical live or on replay:

| Detector        | Fires on                                                        |
|-----------------|-----------------------------------------------------------------|
| Port scan       | one source hitting ≥15 distinct ports in 5 s (SYN scan)         |
| Stealth scan    | NULL / FIN / Xmas TCP flag combinations                         |
| ARP spoofing    | an IP address suddenly claimed by a different MAC               |
| SYN flood       | ≥100 SYNs to one `host:port` in 2 s without handshake           |
| DNS tunneling   | abnormally long / many-label DNS queries (exfil heuristic)      |

Thresholds are configurable in `DetectorConfig`.

**Output** — a live ncurses dashboard for interface capture (protocol mix,
top talkers, scrolling alert feed); a formatted text report and optional JSON
summary for files and scripting/CI. Exit code is non-zero when a critical alert
fires, so it drops into a pipeline.

---

## Architecture

```
                  +-----------+     raw frame bytes
   pcap file /    |  Capture  | --------------------+
   live iface --> | (libpcap) |                     v
                  +-----------+            +--------------------+
                                           |     Dissector      |  bounds-checked
                                           |  Eth/ARP/IP/TCP/   |  ByteReader --
                                           |  UDP/ICMP/DNS      |  never trusts len
                                           +---------+----------+
                                                     | Packet (flat, normalized)
                        +----------------------------+----------------------------+
                        v                            v                            v
                 +-------------+            +------------------+          +--------------+
                 |  FlowTable  |            |    Detector      |          |    Stats     |
                 | 5-tuple +   |            | scan/arp/flood/  |          | proto counts |
                 | TCP state   |            | dns heuristics   |          | throughput   |
                 +------+------+            +---------+--------+          +------+-------+
                        |                             |                          |
                        +-------------+---------------+--------------------------+
                                      v
                          +-----------------------+
                          |  ncurses TUI (live)   |
                          |  text / JSON report   |
                          +-----------------------+
```

Each concern is a separate translation unit behind a header; everything except
`main` lives in a `pktscope_core` static library so the tests link the exact
same code the binary runs.

---

## Build

Prerequisites (Debian/Ubuntu):

```bash
sudo apt install build-essential cmake libpcap-dev libncurses-dev
```

Then:

```bash
./build.sh            # or: mkdir build && cd build && cmake .. && make -j
```

This produces `build/pktscope` and `build/pktscope_tests`.

## Usage

```bash
# analyze a capture file (text report + detections)
pktscope -r capture.pcap

# machine-readable summary for scripting / CI
pktscope -r capture.pcap --json summary.json

# live dashboard (needs root or CAP_NET_RAW)
sudo pktscope -i eth0

# live, filtered with a BPF expression
sudo pktscope -i eth0 -f "tcp port 80 or udp port 53"

# print one line per packet (tcpdump-style)
pktscope -r capture.pcap -v
```

Grant capture capability without full root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./build/pktscope
```

## Testing

```bash
cd build && ./pktscope_tests        # 27 test cases, 600+ assertions
# or: ctest
```

The suite covers the parsers (including hundreds of truncated and random-byte
inputs asserting the parser never crashes — the security-critical property),
each detector's true- and false-positive behavior, flow/TCP-state tracking,
and full-pipeline replay of six crafted `.pcap` files.

Regenerate the sample captures (benign + five attack scenarios) with:

```bash
pip install scapy
python3 tools/make_sample_pcaps.py tests/data
```

---

## Design notes

- **The parser is the attack surface.** A packet analyzer parses attacker-
  controlled bytes by definition, so every read goes through `ByteReader`,
  which throws `ShortBuffer` rather than reading past the end; parsers catch it
  and return "malformed". A fuzz-style test feeds hundreds of truncated and
  random buffers and asserts no crash.
- **Timestamp-driven detection.** Detectors window on the packet's own capture
  time, so a `.pcap` replayed instantly produces the same alerts it would live —
  which is also what makes the detectors unit-testable.
- **Canonical flow keys.** The 5-tuple is sorted so both directions of a
  conversation map to one flow, giving correct byte totals and state tracking.
- **Library + thin main.** All logic sits in `pktscope_core`; `main.cpp` only
  parses arguments and wires capture → dissect → detect → output, so tests
  exercise the real code paths.

## License

MIT
