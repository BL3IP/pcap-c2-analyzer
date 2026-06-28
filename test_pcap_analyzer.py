import os

from pcap_analyzer import analyze

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples", "synthetic-c2.pcap")


def test_dns_query_extracted():
    r = analyze(SAMPLE)
    assert "c2.evil-domain.test" in r["dns_queries"]
    assert "www.example.com" in r["dns_queries"]


def test_http_host_extracted():
    r = analyze(SAMPLE)
    assert "c2.evil-domain.test" in r["http_hosts"]


def test_beaconing_detected():
    r = analyze(SAMPLE)
    assert any(b["dst"] == "185.220.101.50" for b in r["beacons"])
    beacon = next(b for b in r["beacons"] if b["dst"] == "185.220.101.50")
    assert 55 <= beacon["interval_s"] <= 65   # ~60s
    assert beacon["count"] == 6
