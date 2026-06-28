# 16 — Network Traffic Analysis (PCAP → C2 indicators)

A Python **PCAP analyzer** that pulls threat indicators out of a packet capture — DNS queries,
HTTP Host headers, top talkers — and **detects C2 beaconing** (regular call-home intervals).

> Demonstrated on a **safe synthetic capture** crafted in-memory (no real malware traffic). The
> same analyzer runs on real captures from e.g. [malware-traffic-analysis.net](https://malware-traffic-analysis.net).

## Goal
Show network-forensics fundamentals: turn a raw `.pcap` into actionable IOCs and spot the periodic
beaconing pattern that characterizes command-and-control channels.

## What's inside
| Path | What it is |
|------|-----------|
| [`pcap_analyzer.py`](./pcap_analyzer.py) | The analyzer (scapy): DNS/HTTP/talkers + beaconing detection |
| [`scripts/make_sample_pcap.py`](./scripts/make_sample_pcap.py) | Generates the safe synthetic C2 capture |
| [`samples/synthetic-c2.pcap`](./samples/synthetic-c2.pcap) | The test capture (DNS to C2 + 60s HTTP beacons) |

## How beaconing detection works
Group packets by destination, compute inter-arrival deltas, and flag flows whose timing is highly
regular (coefficient of variation `< 0.1`) over ≥4 packets — i.e. a steady "call home" cadence.

## Exact Setup Commands
```powershell
cd C:\Users\banlv\cyber\16-network-traffic-analysis
& "C:\Users\banlv\AppData\Local\Programs\Python\Python312\python.exe" -m venv .venv
.\.venv\Scripts\python.exe -m pip install pytest scapy
.\.venv\Scripts\python.exe scripts\make_sample_pcap.py   # (re)build the sample
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe pcap_analyzer.py samples\synthetic-c2.pcap
```

## Proof It Works
**3/3 tests pass.** Analyzer output on the synthetic capture:
```
DNS queries: c2.evil-domain.test, www.example.com
HTTP hosts : c2.evil-domain.test
Top talkers: 185.220.101.50 (6 pkts), 8.8.8.8 (2 pkts)
Beaconing detected:
  -> 185.220.101.50:80 every ~60.0s x6 (cv=0.0)
```
It correctly recovered the C2 domain (DNS + HTTP Host) and identified the 60-second beacon.

## Screenshots
See [`./screenshots/`](./screenshots). Add: the analyzer output (and the pcap opened in Wireshark).

## My Custom Extensions
- **Beaconing detection** via timing regularity (CV), not just IOC extraction.
- Self-contained: generates its own safe test capture, so it's fully reproducible/offline.
- JSON output feeds straight into `iocsift` (enrich the extracted domains/IPs).

## Resume Bullet Points
- Built a **PCAP analyzer** (Python/scapy) that extracts DNS/HTTP IOCs and **detects C2 beaconing**
  by inter-arrival timing regularity.
- Validated with a generated synthetic C2 capture and a 3-case pytest suite (DNS, HTTP host, beacon).
- Designed output to chain into IOC enrichment tooling.

## Next-Level Ideas
- Run against real malware-traffic-analysis.net captures and document the indicators.
- Add JA3/TLS fingerprinting and DNS-tunneling / data-exfil heuristics.
- Auto-generate a Sigma/Suricata rule from detected beacon destinations.

---
status: ✅ complete & tested
```
✅ PROJECT COMPLETE & FULLY TESTED in its isolated folder. All works. Ready for portfolio.
```
