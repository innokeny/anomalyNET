import scapy.all as scapy
import time
import argparse
from datetime import datetime
import os


def capture_traffic(duration, output_file, interval=300):
    print(f"Starting traffic capture for {duration} seconds...")
    
    start_time = time.time()
    while time.time() - start_time < duration:
        packets = scapy.sniff(timeout=interval)  # Capture packets every 5 minutes
        scapy.wrpcap(output_file, packets, append=True)
        print(f"[{datetime.now()}] Captured {len(packets)} packets.")
        file_size = os.path.getsize(output_file) / (1024 * 1024)  # File size in MB
        print(f"Current file size {output_file}: {file_size:.2f} MB")

def main():
    parser = argparse.ArgumentParser(description="Network traffic capture.")
    parser.add_argument("--duration", type=int, default=15 * 60, help="Traffic capture period in seconds (default is 24 hours).")
    parser.add_argument("--output", type=str, default="network_traffic.pcap", help="Name of the file to save the traffic (default is network_traffic.pcap).")
    parser.add_argument("--interval", type=int, default=300, help="Packet capture interval in seconds (default is 5 minutes).")
    args = parser.parse_args()

    capture_traffic(args.duration, args.output, args.interval)

if __name__ == "__main__":
    main()