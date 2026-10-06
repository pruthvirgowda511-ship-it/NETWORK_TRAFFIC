from collections import Counter
from typing import Dict, Any, List

class TrafficStatistics:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = Counter()
        self.source_ips = Counter()
        self.destination_ips = Counter()
        self.destination_ports = Counter()

    def update(self, packet: Dict[str, Any]) -> None:
        self.total_packets += 1
        self.total_bytes += int(packet.get("length") or 0)

        proto = packet.get("protocol") or "OTHER"
        self.protocols[proto] += 1

        if packet.get("src_ip"):
            self.source_ips[packet["src_ip"]] += 1
        if packet.get("dst_ip"):
            self.destination_ips[packet["dst_ip"]] += 1
        if packet.get("dst_port") is not None:
            self.destination_ports[packet["dst_port"]] += 1

    def snapshot(self) -> Dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocols": dict(self.protocols),
            "top_source_ips": self.source_ips.most_common(10),
            "top_destination_ips": self.destination_ips.most_common(10),
            "top_destination_ports": self.destination_ports.most_common(10),
        }
