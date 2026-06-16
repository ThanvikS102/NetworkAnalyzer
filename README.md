# Network Traffic Analyzer

A Python script that captures live network packets and analyzes them for protocol types, top talkers, and suspicious activity.

## What it does
- Captures live network packets using Scapy
- Displays source IP, destination IP, protocol, and port for each packet
- Summarizes traffic by protocol (TCP, UDP, ICMP)
- Shows top 5 IPs sending the most traffic
- Flags suspicious ports (4444, 1337, 31337)

## Requirements

```bash
pip install scapy
```

## How to run

```bash
sudo python network_analyzer.py
```

> `sudo` is required to capture live packets.

## Sample Output

```
=======================================================
     NETWORK TRAFFIC ANALYZER
=======================================================
Capturing 50 packets...

  [TCP]  192.168.1.5  ->  142.250.77.46  | Port: 443
  [UDP]  192.168.1.5  ->  8.8.8.8        | Port: 53
  [TCP]  192.168.1.8  ->  52.96.12.3     | Port: 80

--- Protocol Summary ---
  TCP        35 packets
  UDP        12 packets
  ICMP        3 packets

--- Top Talkers ---
  192.168.1.5          28 packets

--- Suspicious Activity ---
  None detected.
```

## Author
**Thanvik S**  
GitHub: [github.com/ThanvikS102](https://github.com/ThanvikS102)  
LinkedIn: [linkedin.com/in/thanvik-s-a8a226364](https://linkedin.com/in/thanvik-s-a8a226364)
