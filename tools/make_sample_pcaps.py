#!/usr/bin/env python3
"""Generate sample .pcap files for pktscope: a benign capture plus four attack
scenarios. Requires scapy (`pip install scapy`)."""
import os
import sys

from scapy.all import (ARP, DNS, DNSQR, Ether, ICMP, IP, TCP, UDP, Raw,
                       wrpcap)

OUT = sys.argv[1] if len(sys.argv) > 1 else "tests/data"
os.makedirs(OUT, exist_ok=True)

VICTIM = "192.168.1.10"
ATTACKER = "192.168.1.66"
GATEWAY = "192.168.1.1"
MAC_A = "aa:bb:cc:00:00:66"
MAC_V = "aa:bb:cc:00:00:10"
MAC_GW = "aa:bb:cc:00:00:01"


def eth(src, dst=MAC_V):
    return Ether(src=src, dst=dst)


def benign():
    """Normal web browsing + DNS + a ping. No alerts expected."""
    pkts = []
    t = 0.0
    # DNS lookup
    p = eth(MAC_V, MAC_GW) / IP(src=VICTIM, dst="8.8.8.8") / UDP(sport=51000, dport=53) \
        / DNS(rd=1, qd=DNSQR(qname="www.example.com"))
    p.time = t; pkts.append(p); t += 0.05
    # a full TCP handshake + data to a web server, port 443
    for i in range(3):
        sp = 40000 + i
        h1 = eth(MAC_V, MAC_GW) / IP(src=VICTIM, dst="93.184.216.34") / TCP(sport=sp, dport=443, flags="S", seq=1000)
        h2 = eth(MAC_GW) / IP(src="93.184.216.34", dst=VICTIM) / TCP(sport=443, dport=sp, flags="SA", seq=5000, ack=1001)
        h3 = eth(MAC_V, MAC_GW) / IP(src=VICTIM, dst="93.184.216.34") / TCP(sport=sp, dport=443, flags="A", seq=1001, ack=5001)
        data = eth(MAC_V, MAC_GW) / IP(src=VICTIM, dst="93.184.216.34") / TCP(sport=sp, dport=443, flags="PA", seq=1001, ack=5001) / Raw(b"x" * 400)
        for p in (h1, h2, h3, data):
            p.time = t; pkts.append(p); t += 0.02
    # ICMP ping
    p = eth(MAC_V, MAC_GW) / IP(src=VICTIM, dst=GATEWAY) / ICMP()
    p.time = t; pkts.append(p)
    wrpcap(f"{OUT}/benign.pcap", pkts)
    print(f"benign.pcap: {len(pkts)} packets")


def port_scan():
    """nmap-style SYN scan: one source, 40 ports, tight timing."""
    pkts = []
    t = 0.0
    for port in list(range(20, 55)) + [80, 443, 3306, 8080, 22]:
        p = eth(MAC_A) / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=44444, dport=port, flags="S")
        p.time = t; pkts.append(p); t += 0.01
    wrpcap(f"{OUT}/port_scan.pcap", pkts)
    print(f"port_scan.pcap: {len(pkts)} packets")


def stealth_scan():
    """NULL, FIN, and Xmas scan packets."""
    pkts = []
    t = 0.0
    for port, flags in [(80, ""), (81, "F"), (82, "FPU"), (83, "F"), (84, "")]:
        p = eth(MAC_A) / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=44445, dport=port, flags=flags)
        p.time = t; pkts.append(p); t += 0.1
    wrpcap(f"{OUT}/stealth_scan.pcap", pkts)
    print(f"stealth_scan.pcap: {len(pkts)} packets")


def arp_spoof():
    """Attacker claims the gateway IP with its own MAC (cache poisoning)."""
    pkts = []
    t = 0.0
    # legit gateway announces itself
    p = Ether(src=MAC_GW, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=GATEWAY, hwsrc=MAC_GW, pdst=VICTIM)
    p.time = t; pkts.append(p); t += 0.5
    # attacker forges gateway->its MAC repeatedly
    for _ in range(3):
        p = Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=GATEWAY, hwsrc=MAC_A, pdst=VICTIM)
        p.time = t; pkts.append(p); t += 0.5
    wrpcap(f"{OUT}/arp_spoof.pcap", pkts)
    print(f"arp_spoof.pcap: {len(pkts)} packets")


def syn_flood():
    """150 SYNs to one port from spoofed sources within ~1.5s."""
    pkts = []
    t = 0.0
    for i in range(150):
        src = f"10.0.{(i // 250) % 256}.{i % 250 + 1}"
        p = eth(MAC_A) / IP(src=src, dst=VICTIM) / TCP(sport=1024 + (i % 5000), dport=80, flags="S")
        p.time = t; pkts.append(p); t += 0.01
    wrpcap(f"{OUT}/syn_flood.pcap", pkts)
    print(f"syn_flood.pcap: {len(pkts)} packets")


def dns_tunnel():
    """Suspiciously long DNS queries (data exfil over DNS)."""
    pkts = []
    t = 0.0
    for i in range(4):
        qname = f"{'a1b2c3d4e5f6' * 3}.seg{i}.tunnel.evil-exfil-domain.com"
        p = eth(MAC_V, MAC_GW) / IP(src=VICTIM, dst="8.8.8.8") / UDP(sport=52000 + i, dport=53) \
            / DNS(rd=1, qd=DNSQR(qname=qname))
        p.time = t; pkts.append(p); t += 0.2
    wrpcap(f"{OUT}/dns_tunnel.pcap", pkts)
    print(f"dns_tunnel.pcap: {len(pkts)} packets")


if __name__ == "__main__":
    benign()
    port_scan()
    stealth_scan()
    arp_spoof()
    syn_flood()
    dns_tunnel()
    print(f"\nWrote sample pcaps to {OUT}/")
