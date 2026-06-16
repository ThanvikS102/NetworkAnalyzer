"""
Network Traffic Analyzer - SOC Portfolio Project
Author: Thanvik S

Run with: sudo python network_analyzer.py
(sudo needed to capture live packets)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict

# How many packets to capture
PACKET_COUNT = 50

# Track stats
protocol_count = defaultdict(int)
ip_count = defaultdict(int)
suspicious = []

def analyze_packet(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    ip_count[src] += 1

    # Identify protocol
    if packet.haslayer(TCP):
        proto = "TCP"
        port = packet[TCP].dport

        # Flag suspicious ports
        if port in [4444, 1337, 31337]:
            suspicious.append(f"Suspicious port {port} from {src} -> {dst}")

    elif packet.haslayer(UDP):
        proto = "UDP"
        port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        proto = "ICMP"
        port = "-"

    else:
        proto = "OTHER"
        port = "-"

    protocol_count[proto] += 1
    print(f"  [{proto}]  {src}  ->  {dst}  | Port: {port}")


# ── Capture Packets ──
print("=" * 55)
print("     NETWORK TRAFFIC ANALYZER")
print("=" * 55)
print(f"Capturing {PACKET_COUNT} packets... (Ctrl+C to stop early)\n")

sniff(prn=analyze_packet, count=PACKET_COUNT, store=False)

# ── Print Report ──
print("\n--- Protocol Summary ---")
for proto, count in sorted(protocol_count.items(), key=lambda x: x[1], reverse=True):
    print(f"  {proto:<10} {count} packets")

print("\n--- Top Talkers (IPs sending most traffic) ---")
top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]
for ip, count in top_ips:
    print(f"  {ip:<20} {count} packets")

print("\n--- Suspicious Activity ---")
if suspicious:
    for alert in suspicious:
        print(f"  [!] {alert}")
else:
    print("  None detected.")

print("\n" + "=" * 55)
