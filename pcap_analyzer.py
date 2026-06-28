"""pcap_analyzer - extract C2 / threat indicators from a packet capture.

Surfaces DNS queries, HTTP Host headers, top talkers, and detects periodic **beaconing**
(regular intervals to the same destination) - a hallmark of C2 channels.

Usage:
    python pcap_analyzer.py <capture.pcap> [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, rdpcap


def analyze(pcap_path: str) -> dict:
    packets = rdpcap(pcap_path)
    dns_queries = set()
    http_hosts = set()
    conversations = defaultdict(list)   # (dst, dport) -> [timestamps]
    talkers = defaultdict(int)          # dst ip -> packet count

    for p in packets:
        if p.haslayer(DNS) and p[DNS].qr == 0 and p[DNS].qd is not None:
            try:
                dns_queries.add(p[DNSQR].qname.decode(errors="ignore").rstrip("."))
            except Exception:  # noqa: BLE001
                pass
        if p.haslayer(Raw) and p.haslayer(TCP):
            payload = bytes(p[Raw].load)
            if payload[:4] in (b"GET ", b"POST", b"HEAD") or b"HTTP/1." in payload[:64]:
                for line in payload.split(b"\r\n"):
                    if line[:5].lower() == b"host:":
                        http_hosts.add(line.split(b":", 1)[1].strip().decode(errors="ignore"))
        if p.haslayer(IP):
            ip = p[IP]
            talkers[ip.dst] += 1
            dport = p[TCP].dport if p.haslayer(TCP) else (p[UDP].dport if p.haslayer(UDP) else 0)
            conversations[(ip.dst, dport)].append(float(p.time))

    beacons = []
    for (dst, dport), times in conversations.items():
        if len(times) >= 4:
            times = sorted(times)
            deltas = [b - a for a, b in zip(times, times[1:])]
            mean = sum(deltas) / len(deltas)
            if mean > 0:
                std = (sum((d - mean) ** 2 for d in deltas) / len(deltas)) ** 0.5
                cv = std / mean  # coefficient of variation - low = very regular
                if cv < 0.1:
                    beacons.append({"dst": dst, "dport": dport,
                                    "interval_s": round(mean, 1), "count": len(times),
                                    "regularity_cv": round(cv, 3)})

    top_talkers = sorted(talkers.items(), key=lambda kv: -kv[1])[:5]
    return {
        "packets": len(packets),
        "dns_queries": sorted(dns_queries),
        "http_hosts": sorted(http_hosts),
        "top_talkers": [{"dst": d, "packets": c} for d, c in top_talkers],
        "beacons": beacons,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pcap_analyzer", description="Extract C2 indicators from a pcap.")
    ap.add_argument("pcap")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    r = analyze(args.pcap)
    if args.json:
        print(json.dumps(r, indent=2))
        return 0
    print(f"Packets: {r['packets']}")
    print(f"DNS queries: {', '.join(r['dns_queries']) or '-'}")
    print(f"HTTP hosts : {', '.join(r['http_hosts']) or '-'}")
    print("Top talkers:")
    for t in r["top_talkers"]:
        print(f"  {t['dst']}  ({t['packets']} pkts)")
    print("Beaconing detected:" if r["beacons"] else "Beaconing detected: none")
    for b in r["beacons"]:
        print(f"  -> {b['dst']}:{b['dport']} every ~{b['interval_s']}s x{b['count']} (cv={b['regularity_cv']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
