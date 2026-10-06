import argparse
from capture.packet_capture import start_capture, list_interfaces
from storage.database import init_db

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--iface", default=None, help="Network interface name")
    parser.add_argument("--count", type=int, default=0, help="Packets to capture, 0 = unlimited")
    args = parser.parse_args()

    init_db()

    if args.list_interfaces:
        for i, iface in enumerate(list_interfaces(), start=1):
            print(f"{i}. {iface}")
        return

    print("Starting packet capture. Press Ctrl+C to stop.")
    start_capture(interface=args.iface, packet_count=args.count)

if __name__ == "__main__":
    main()
