# Network Traffic Analyzer with Packet Sniffing and Basic Anomaly Detection

Educational mini-project for analyzing packet metadata on networks you own or are authorized to monitor.

## Features

- Live packet capture using Scapy
- IPv4, TCP, UDP, ICMP, DNS and ARP identification
- Packet metadata extraction
- SQLite storage
- Basic threshold-based anomaly detection:
  - high packet rate
  - port scan-like behavior
  - ICMP spike
  - SYN spike
- Streamlit dashboard
- Protocol and source-IP visualizations
- Unit tests for anomaly detection

## Project flow

Network Interface
    -> Scapy packet capture
    -> Packet parser
    -> SQLite database
    -> Anomaly detector
    -> Alerts
    -> Streamlit dashboard

## Windows setup

1. Install Python 3.11 or newer.
2. Install Npcap from the official Npcap website.
3. During Npcap installation, enable WinPcap API-compatible mode if offered.
4. Open PowerShell or Command Prompt as Administrator.
5. Create a virtual environment:

    python -m venv venv

6. Activate it:

    venv\Scripts\activate

7. Install dependencies:

    pip install -r requirements.txt

## List network interfaces

    python app.py --list-interfaces

## Start packet capture

Capture on the default interface:

    python app.py

Or specify one:

    python app.py --iface "YOUR_INTERFACE_NAME"

Stop with Ctrl+C.

## Open dashboard

Keep packet capture running in one terminal and open a second terminal:

    streamlit run dashboard/dashboard.py

The browser should open automatically.

## Testing

Install pytest:

    pip install pytest

Then run:

    pytest

## Important networking concepts

### Packet
A packet is a small unit of data transmitted across a network.

### Packet sniffing
Packet sniffing means observing packets that pass through a network interface. This project only stores packet metadata, not application payload contents.

### TCP vs UDP
TCP is connection-oriented and reliable. UDP is connectionless and has lower overhead.

### Port
A port identifies the application/service receiving network traffic. For example, HTTPS commonly uses TCP port 443.

### TCP SYN
SYN is a TCP flag used when beginning a TCP connection. A sudden large number of SYN packets can be unusual, but it does not automatically prove an attack.

## Anomaly detection

This project uses simple thresholds because they are easy to understand and explain in a viva.

### High packet rate
If one source sends more than PACKET_RATE_THRESHOLD packets within PACKET_RATE_WINDOW seconds, an alert is generated.

### Port scan-like behavior
If one source contacts more than PORT_SCAN_THRESHOLD different destination ports during PORT_SCAN_WINDOW seconds, the system generates a potential port-scan-like alert.

### ICMP spike
A source producing unusually many ICMP packets in a short period is flagged.

### SYN spike
A source producing unusually many TCP SYN packets in a short period is flagged.

These are indicators only, not proof of malicious activity. False positives are possible.

## Privacy

This project intentionally focuses on packet metadata such as IP addresses, protocols, ports, packet lengths and TCP flags. It does not attempt to extract passwords, cookies, private messages or other payload contents.
