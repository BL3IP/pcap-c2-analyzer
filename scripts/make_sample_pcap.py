"""Generate a SAFE synthetic C2 capture for the analyzer demo/tests.
No real malware or traffic - packets are crafted in-memory with scapy.

Output: ../samples/synthetic-c2.pcap
"""
import os

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "samples", "synthetic-c2.pcap")

pkts = []

# DNS lookup of the C2 domain
d = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname="c2.evil-domain.test"))
d.time = 0.0
pkts.append(d)

# A benign DNS lookup
b = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=50001, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.example.com"))
b.time = 1.0
pkts.append(b)

# HTTP beacons to a C2 IP every 60s (regular interval = beaconing)
for i, t in enumerate([0, 60, 120, 180, 240, 300]):
    p = (IP(src="10.0.0.5", dst="185.220.101.50")
         / TCP(sport=40000 + i, dport=80, flags="PA")
         / Raw(load=b"GET /gate.php HTTP/1.1\r\nHost: c2.evil-domain.test\r\nUser-Agent: beacon\r\n\r\n"))
    p.time = float(t) + 2
    pkts.append(p)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
wrpcap(OUT, pkts)
print(f"Wrote {OUT} ({len(pkts)} packets)")
