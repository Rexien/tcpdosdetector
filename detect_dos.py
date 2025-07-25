from scapy.all import rdpcap, TCP, IP, ICMP, UDP, DNS
from collections import defaultdict
import datetime

# Thresholds
SYN_THRESHOLD = 100
ICMP_THRESHOLD = 100
DNS_THRESHOLD = 50

# Counters
syn_counts = defaultdict(int)
icmp_counts = defaultdict(int)
dns_counts = defaultdict(int)

# Load PCAP
packets = rdpcap("sample.pcap")

for pkt in packets:
    if IP in pkt:
        src_ip = pkt[IP].src

        # SYN Flood Detection
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            syn_counts[src_ip] += 1

        # ICMP Flood Detection
        elif pkt.haslayer(ICMP):
            icmp_counts[src_ip] += 1

        # DNS Port Flood Detection (port 53 UDP or TCP)
        elif pkt.haslayer(UDP) and pkt[UDP].dport == 53:
            dns_counts[src_ip] += 1
        elif pkt.haslayer(TCP) and pkt[TCP].dport == 53:
            dns_counts[src_ip] += 1

# Output
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"\n[+] DoS Analysis Report — {now}\n")

def log_if_exceeds(threshold, count_dict, attack_name):
    for ip, count in count_dict.items():
        if count > threshold:
            print(f"[!] {attack_name} detected from {ip} — {count} packets")

log_if_exceeds(SYN_THRESHOLD, syn_counts, "SYN Flood")
log_if_exceeds(ICMP_THRESHOLD, icmp_counts, "ICMP Flood")
log_if_exceeds(DNS_THRESHOLD, dns_counts, "DNS Flood")

print("\n[+] Analysis Complete.")
# Save to log.txt
with open("dos_report.txt", "w") as f:
    f.write(f"DoS Analysis Report — {now}\n\n")
    for ip, count in syn_counts.items():
        if count > SYN_THRESHOLD:
            f.write(f"SYN Flood detected from {ip} — {count} packets\n")
    for ip, count in icmp_counts.items():
        if count > ICMP_THRESHOLD:
            f.write(f"ICMP Flood detected from {ip} — {count} packets\n")
    for ip, count in dns_counts.items():
        if count > DNS_THRESHOLD:
            f.write(f"DNS Flood detected from {ip} — {count} packets\n")
    f.write("\nAnalysis Complete.\n")
