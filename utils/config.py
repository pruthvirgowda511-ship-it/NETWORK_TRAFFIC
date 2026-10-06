PACKET_RATE_WINDOW = 10
PACKET_RATE_THRESHOLD = 100

PORT_SCAN_WINDOW = 10
PORT_SCAN_THRESHOLD = 20

ICMP_WINDOW = 10
ICMP_THRESHOLD = 30

SYN_WINDOW = 10
SYN_THRESHOLD = 40

TRAFFIC_VOLUME_WINDOW = 10
Z_SCORE_THRESHOLD = 3.0

# Minimum seconds between two alerts of the same type for the same source.
# Without this, a sustained condition emits one alert per packet.
ALERT_COOLDOWN = 10

from pathlib import Path

# Anchored to the project root so the capture process and the dashboard always
# agree on the database location, whatever directory each was launched from.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = str(PROJECT_ROOT / "data" / "traffic.db")
