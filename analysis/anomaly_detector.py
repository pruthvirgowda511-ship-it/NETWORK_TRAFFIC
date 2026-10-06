from collections import defaultdict, deque
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Dict, Any, List
from utils import config

class AnomalyDetector:
    def __init__(self):
        self.packet_times = defaultdict(deque)
        self.icmp_times = defaultdict(deque)
        self.syn_times = defaultdict(deque)
        self.port_events = defaultdict(deque)
        self.volume_history = deque(maxlen=30)
        self.last_alert = {}

    def _cooled_down(self, kind: str, src: str, now: datetime) -> bool:
        """True if enough time has passed to re-report this condition.

        A threshold breach stays true for every packet that follows it, so
        without this guard one sustained event writes an alert row per packet.
        """
        key = (src, kind)
        previous = self.last_alert.get(key)
        if previous is not None and (now - previous).total_seconds() < config.ALERT_COOLDOWN:
            return False
        self.last_alert[key] = now
        return True

    def _trim(self, q, window_seconds: int, now: datetime):
        cutoff = now - timedelta(seconds=window_seconds)
        while q and q[0][0] < cutoff:
            q.popleft()

    def process(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        now = datetime.now()
        src = packet.get("src_ip")
        dst = packet.get("dst_ip")
        if not src:
            return alerts

        # High packet rate
        q = self.packet_times[src]
        q.append((now, 1))
        self._trim(q, config.PACKET_RATE_WINDOW, now)
        if len(q) > config.PACKET_RATE_THRESHOLD and self._cooled_down("High packet rate", src, now):
            alerts.append(self._alert(
                "High packet rate", src, dst, len(q),
                config.PACKET_RATE_THRESHOLD,
                f"{len(q)} packets in {config.PACKET_RATE_WINDOW}s"
            ))

        # Port scan-like pattern
        dport = packet.get("dst_port")
        if dport is not None:
            pq = self.port_events[src]
            pq.append((now, int(dport)))
            self._trim(pq, config.PORT_SCAN_WINDOW, now)
            unique_ports = len({port for _, port in pq})
            if unique_ports > config.PORT_SCAN_THRESHOLD and self._cooled_down("Potential port scan-like behavior", src, now):
                alerts.append(self._alert(
                    "Potential port scan-like behavior", src, dst, unique_ports,
                    config.PORT_SCAN_THRESHOLD,
                    f"{unique_ports} unique destination ports in {config.PORT_SCAN_WINDOW}s"
                ))

        # ICMP spike
        if packet.get("protocol") == "ICMP":
            iq = self.icmp_times[src]
            iq.append((now, 1))
            self._trim(iq, config.ICMP_WINDOW, now)
            if len(iq) > config.ICMP_THRESHOLD and self._cooled_down("Potential ICMP flood-like behavior", src, now):
                alerts.append(self._alert(
                    "Potential ICMP flood-like behavior", src, dst, len(iq),
                    config.ICMP_THRESHOLD,
                    f"{len(iq)} ICMP packets in {config.ICMP_WINDOW}s"
                ))

        # SYN spike
        if packet.get("protocol") == "TCP" and packet.get("tcp_flags") == "S":
            sq = self.syn_times[src]
            sq.append((now, 1))
            self._trim(sq, config.SYN_WINDOW, now)
            if len(sq) > config.SYN_THRESHOLD and self._cooled_down("Potential SYN flood-like behavior", src, now):
                alerts.append(self._alert(
                    "Potential SYN flood-like behavior", src, dst, len(sq),
                    config.SYN_THRESHOLD,
                    f"{len(sq)} SYN packets in {config.SYN_WINDOW}s"
                ))

        return alerts

    def evaluate_volume(self, packets_in_window: int) -> List[Dict[str, Any]]:
        alerts = []
        if len(self.volume_history) >= 5:
            mu = mean(self.volume_history)
            sigma = pstdev(self.volume_history)
            if sigma > 0:
                z = (packets_in_window - mu) / sigma
                if z > config.Z_SCORE_THRESHOLD:
                    alerts.append({
                        "timestamp": datetime.now().isoformat(timespec="seconds"),
                        "source_ip": "N/A",
                        "destination_ip": "N/A",
                        "type": "Unusual traffic volume",
                        "reason": f"Traffic volume z-score is {z:.2f}",
                        "observed_value": packets_in_window,
                        "threshold": config.Z_SCORE_THRESHOLD,
                        "severity": "Medium",
                    })
        self.volume_history.append(packets_in_window)
        return alerts

    @staticmethod
    def _alert(kind, src, dst, observed, threshold, reason):
        return {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "source_ip": src,
            "destination_ip": dst or "N/A",
            "type": kind,
            "reason": reason,
            "observed_value": observed,
            "threshold": threshold,
            "severity": "Medium",
        }
