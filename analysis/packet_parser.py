from datetime import datetime
from typing import Dict, Any
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS

def parse_packet(packet) -> Dict[str, Any]:
    info = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "length": len(packet),
        "tcp_flags": None,
        "ttl": None,
    }

    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst
        info["ttl"] = int(packet[IP].ttl)

        if TCP in packet:
            info["protocol"] = "TCP"
            info["src_port"] = int(packet[TCP].sport)
            info["dst_port"] = int(packet[TCP].dport)
            info["tcp_flags"] = str(packet[TCP].flags)
        elif UDP in packet:
            info["protocol"] = "UDP"
            info["src_port"] = int(packet[UDP].sport)
            info["dst_port"] = int(packet[UDP].dport)
        elif ICMP in packet:
            info["protocol"] = "ICMP"

        if DNS in packet:
            info["protocol"] = "DNS"

    elif ARP in packet:
        info["protocol"] = "ARP"
        info["src_ip"] = packet[ARP].psrc
        info["dst_ip"] = packet[ARP].pdst

    return info
