import os
import argparse
from scapy.all import *

def analyze_pcap(pcap_files, target_address):
    port_counts = {}

    for pcap_file in pcap_files:
        # Load the pcap file
        packets = rdpcap(pcap_file)

        # Filter packets to only those involving the target address
        target_packets = [pkt for pkt in packets if IP in pkt and (pkt[IP].src == target_address or pkt[IP].dst == target_address)]

        if not target_packets:
            print(f"No packets found involving the target address in file: {pcap_file}")
            continue

        print(f"Found {len(target_packets)} packets involving the target address {target_address} in file: {pcap_file}")

        # Extract information about each packet involving the target address
        for pkt in target_packets:
            src_port = pkt[IP].sport
            dst_port = pkt[IP].dport

            if (pkt[IP].src, pkt[IP].dst, src_port) in port_counts:
                port_counts[(pkt[IP].src, pkt[IP].dst, src_port)] += 1
            else:
                port_counts[(pkt[IP].src, pkt[IP].dst, src_port)] = 1

            if (pkt[IP].dst, pkt[IP].src, dst_port) in port_counts:
                port_counts[(pkt[IP].dst, pkt[IP].src, dst_port)] += 1
            else:
                port_counts[(pkt[IP].dst, pkt[IP].src, dst_port)] = 1

    print("\nSummary of communication:")
    for key, value in port_counts.items():
        src_addr, dst_addr, port = key
        print(f"{src_addr}:{port} <--> {dst_addr}:{port}: {value} times")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze pcap files for IP address interactions.")
    parser.add_argument("-p", "--path", help="Path to pcap file or folder containing pcap files (* for all files)", required=True)
    parser.add_argument("-i", "--ip", help="Target IP address to analyze", required=True)
    args = parser.parse_args()

    # Resolve wildcard in path
    pcap_files = []
    if '*' in args.path:
        folder_path = args.path.replace('*', '')
        for file_name in os.listdir(folder_path):
            if file_name.endswith('.pcap'):
                pcap_files.append(os.path.join(folder_path, file_name))
    else:
        pcap_files.append(args.path)

    # Analyze the pcap files
    analyze_pcap(pcap_files, args.ip)
