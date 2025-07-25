from scapy.all import rdpcap, TCP, IP, ICMP, UDP, DNS

def analyze_packets(packets):
    syn_count = {}
    icmp_count = {}
    dns_count = {}

    for pkt in packets:
        print(pkt.summary())       # (2) Print summary
        # pkt.show()               # (3) Uncomment this for detailed view of each packet

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

            if TCP in pkt and pkt[TCP].flags == "S":  # SYN flood detection
                key = (src, dst)
                syn_count[key] = syn_count.get(key, 0) + 1

            elif ICMP in pkt:  # ICMP flood detection
                key = (src, dst)
                icmp_count[key] = icmp_count.get(key, 0) + 1

            elif UDP in pkt and pkt[UDP].dport == 53 and DNS in pkt:  # DNS flood detection
                key = (src, dst)
                dns_count[key] = dns_count.get(key, 0) + 1

    print("\n=== FLOOD ANALYSIS REPORT ===")
    for (src, dst), count in syn_count.items():
        if count > 100:
            print(f"SYN Flood Detected: ({src} → {dst}) = {count} SYN packets")

    for (src, dst), count in icmp_count.items():
        if count > 100:
            print(f"ICMP Flood Detected: ({src} → {dst}) = {count} ICMP packets")

    for (src, dst), count in dns_count.items():
        if count > 100:
            print(f"DNS Flood Detected: ({src} → {dst}) = {count} DNS packets")


if __name__ == "__main__":
    pcap_file = "sample.pcap"
    print(f"Loading packets from {pcap_file}...\n")
    packets = rdpcap(pcap_file)

    analyze_packets(packets)
