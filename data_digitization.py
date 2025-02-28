import scapy.all as scapy
import pandas as pd
import ipaddress
import numpy as np


# Converts IP address (IPv4/IPv6) to numerical features.
# Returns:
# - For IPv4: [octet1, octet2, octet3, octet4, 0, 0, 0, 0, 0, is_ipv6]
# - For IPv6: [group1, group2, ..., group8, is_ipv6]
def ip_to_features(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        features = []
        
        if ip.version == 4:
            # IPv4: 4 octets, normalized [0-1]
            octets = list(ip.packed)
            features = [x / 255.0 for x in octets]
            features += [0.0] * 4  # Fill up to 8 values
            features.append(0)      # is_ipv6 = False
            
        elif ip.version == 6:
            # IPv6: 8 groups of 16 bits, normalized [0-1]
            groups = list(ip.packed)
            for i in range(0, 16, 2):
                chunk = groups[i:i+2]
                value = int.from_bytes(chunk, byteorder='big')
                features.append(value / 65535.0)
            features.append(1)      # is_ipv6 = True
            
        return features
        
    except ValueError:
        return [0.0] * 8 + [0]  # Invalid address

def extract_features(packet):
    features = []
    
    # Packet length
    features.append(len(packet))
    
    # IP layer
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        src_features = ip_to_features(ip_layer.src)
        dst_features = ip_to_features(ip_layer.dst)
    elif packet.haslayer(scapy.IPv6):
        ip_layer = packet[scapy.IPv6]
        src_features = ip_to_features(ip_layer.src)
        dst_features = ip_to_features(ip_layer.dst)
    else:
        src_features = [0.0] * 9
        dst_features = [0.0] * 9
    
    features += src_features + dst_features
    
    # Other features (TTL, proto, ports...)
    if packet.haslayer(scapy.IP):
        features.append(packet[scapy.IP].ttl / 255.0)
        features.append(packet[scapy.IP].proto / 255.0)
    elif packet.haslayer(scapy.IPv6):
        features.append(packet[scapy.IPv6].hlim / 255.0)
        features.append(packet[scapy.IPv6].nh / 255.0)
    else:
        features.extend([0.0, 0.0])
    
    # Transport layer
    for layer in [scapy.TCP, scapy.UDP]:
        if packet.haslayer(layer):
            transport = packet[layer]
            features.append(transport.sport / 65535.0)
            features.append(transport.dport / 65535.0)
            if layer == scapy.TCP:
                features.append(int(transport.flags) / 255.0)
            else:
                features.append(0.0)
            break
    else:
        features.extend([0.0, 0.0, 0.0])
    
    return features

# Create DataFrame
columns = [
    'length',
    'src_ip1', 'src_ip2', 'src_ip3', 'src_ip4', 'src_ip5', 'src_ip6', 'src_ip7', 'src_ip8', 'src_is_ipv6',
    'dst_ip1', 'dst_ip2', 'dst_ip3', 'dst_ip4', 'dst_ip5', 'dst_ip6', 'dst_ip7', 'dst_ip8', 'dst_is_ipv6',
    'ttl', 'proto', 
    'sport', 'dport', 'flags'
]

def pcap_to_matrix(pcap_file, output_csv=None):
    packets = scapy.rdpcap(pcap_file)
    data = [extract_features(p) for p in packets]
    df = pd.DataFrame(data, columns=columns)
    
    if output_csv:
        df.to_csv(output_csv, index=False)
    
    return df

def main():
    pcap_file = "network_traffic.pcap"
    output_csv = "traffic_features.csv"

    df = pcap_to_matrix(pcap_file, output_csv)

    print("\nFirst 5 rows of data:")
    print(df.head())

if __name__ == "__main__":
    main()