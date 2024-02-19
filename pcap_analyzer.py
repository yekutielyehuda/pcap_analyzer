import sys
from scapy.all import *

def analyze_pcap(pcap_path, target_ip):
    packets = rdpcap(pcap_path)
    target_packets = [pkt for pkt in packets if IP in pkt and pkt[IP].src == target_ip or pkt[IP].dst == target_ip]

    print(f"Total packets involving {target_ip}: {len(target_packets)}")
    
    # Print information about each packet involving the target IP
    for i, pkt in enumerate(target_packets, start=1):
        print(f"\nPacket {i}:")
        print(pkt.summary())

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python pcap_analyzer.py <pcap_path> <target_ip>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    target_ip = sys.argv[2]

    analyze_pcap(pcap_path, target_ip)
