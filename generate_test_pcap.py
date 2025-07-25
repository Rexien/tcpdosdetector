from scapy.all import IP, TCP, ICMP, UDP, DNS, DNSQR, wrpcap

def generate_syn_flood():
    return [IP(src="192.168.1.100", dst="10.0.0.1") / TCP(dport=80, flags="S") for _ in range(200)]

def generate_icmp_flood():
    return [IP(src="192.168.1.200", dst="10.0.0.1") / ICMP() for _ in range(200)]

def generate_dns_flood():
    return [
        IP(src="192.168.1.150", dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        for _ in range(200)
    ]

if __name__ == "__main__":
    packets = generate_syn_flood() + generate_icmp_flood() + generate_dns_flood()
    wrpcap("sample.pcap", packets)
