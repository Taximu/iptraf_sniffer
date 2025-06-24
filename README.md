![Alt text](https://upload.wikimedia.org/wikipedia/commons/a/ab/Cb_ts_sniffing_advanced.033.1.1.png)

# 🕵️‍♂️ IP Traffic Sniffer (C#)

A simple and lightweight C# tool that captures and logs IP network traffic. This utility can be used to monitor, inspect, and analyze IPv4 packets flowing through a network interface in real time.

---

## 📦 What This Repository Contains

- **Core packet capture logic** using raw sockets or WinPcap (depending on implementation)
- **Packet parser** to decode IP headers and extract key fields:
  - Source & destination IP addresses  
  - Protocol (TCP, UDP, ICMP, etc.)  
  - Packet length and other metadata
- **Logging output** to console or file for analysis
- **Extensible code structure**—easily plug in custom filters or handlers

---

## ⚙️ Key Features

- Real‑time capture of IPv4 traffic
- Support for multiple protocols (TCP/UDP/ICMP)
- Decodes header information and displays it in a readable format
- Lightweight and easy to integrate into C#/.NET projects

---

## 🚀 Getting Started

### Requirements
- **Windows or Linux** (with appropriate privileges for raw sockets)
- [.NET SDK (6.0+)](https://dotnet.microsoft.com/)
- *(Optional)* WinPcap or Npcap installed for advanced packet capture

### Build & Run

```bash
git clone https://github.com/Taximu/iptraf_sniffer.git
cd iptraf_sniffer

# Build
dotnet build

# Run the sniffer
dotnet run --project src/iptraf_sniffer.csproj

