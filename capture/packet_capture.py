from scapy.all import sniff, get_if_list
from analysis.packet_parser import parse_packet
from analysis.anomaly_detector import AnomalyDetector
from storage.database import init_db, save_packet, save_alert

detector = AnomalyDetector()

def list_interfaces():
    return get_if_list()

def start_capture(interface=None, packet_count=0):
    init_db()

    def handle(packet):
        parsed = parse_packet(packet)
        save_packet(parsed)

        for alert in detector.process(parsed):
            save_alert(alert)
            print(f"[ALERT] {alert['type']} - {alert['reason']}")

        print(
            f"{parsed['timestamp']} | "
            f"{parsed['src_ip']} -> {parsed['dst_ip']} | "
            f"{parsed['protocol']} | {parsed['length']} bytes"
        )

    sniff(
        iface=interface or None,
        prn=handle,
        store=False,
        count=packet_count
    )
