# 🛡️ DoS Detection Tool with Tcpdump Log Analysis

A Python-powered CLI tool that scans and analyzes `tcpdump` log files to detect potential **Denial-of-Service (DoS)** attack patterns, including **SYN floods**, **ICMP floods**, and **DNS (port 53) abuses**.



Features

- ✅ **Log Parsing**: Read and analyze tcpdump output files efficiently.
- ✅ **SYN Flood Detection**: Identify rapid, repeated TCP SYN requests from single or multiple IPs.
- ✅ **ICMP Flood Alerts**: Detect excessive ICMP echo requests (ping floods).
- ✅ **DNS Flood Recognition**: Monitor UDP traffic targeting port 53 for anomalies.
- ✅ **Command-Line Interface**: Easy to use, lightweight, and fast.



Example Use Case

```bash
python detect_dos.py -f sample.pcap
