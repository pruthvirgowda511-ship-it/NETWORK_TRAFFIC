from analysis.anomaly_detector import AnomalyDetector
from utils import config

def make_packet(src="10.0.0.1", dst="10.0.0.2", protocol="TCP", dport=80, flags="A"):
    return {
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "dst_port": dport,
        "tcp_flags": flags,
        "length": 60,
    }

def test_port_scan_detection():
    detector = AnomalyDetector()
    old = config.PORT_SCAN_THRESHOLD
    config.PORT_SCAN_THRESHOLD = 3
    found = False
    try:
        for port in [21, 22, 23, 25]:
            alerts = detector.process(make_packet(dport=port))
            found = found or any("port scan" in a["type"].lower() for a in alerts)
        assert found
    finally:
        config.PORT_SCAN_THRESHOLD = old

def test_syn_spike_detection():
    detector = AnomalyDetector()
    old = config.SYN_THRESHOLD
    config.SYN_THRESHOLD = 2
    found = False
    try:
        for _ in range(3):
            alerts = detector.process(make_packet(flags="S"))
            found = found or any("syn flood" in a["type"].lower() for a in alerts)
        assert found
    finally:
        config.SYN_THRESHOLD = old
