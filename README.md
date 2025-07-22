# XSS-Wing

<img width="400" alt="XSS-Wing Logo" src="https://github.com/user-attachments/assets/7c854ace-bdad-4a1f-be8a-31447e4b54fa" />

**XSS-Wing** is a simple Python tool that intercepts HTTP traffic and injects custom JavaScript payloads into HTML responses in real time.  
It leverages `scapy` and `netfilterqueue` libraries to manipulate packets on the fly, allowing penetration testers and security enthusiasts to demonstrate and analyze XSS injection attacks on local networks.

---

## Features

- Captures HTTP traffic on port 80.
- Strips `Accept-Encoding` headers to force uncompressed content.
- Injects customizable JavaScript payloads into HTTP responses.
- Maintains packet integrity by recalculating IP and TCP checksums.
- Logs HTTP request and response events for easy monitoring.

---

## Requirements

- Python 3.x
- `scapy`
- `netfilterqueue`
- Root privileges (necessary to intercept and modify network packets)
- Linux system with `iptables` available

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/OctoDev4/XSS-Wing.git
cd XSS-Wing
```
2. Install required Python packages:
```bash
pip install scapy netfilterqueue
  ```
3. Setup iptables to redirect HTTP packets to NetfilterQueue (queue number 0 used here):
```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -I INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0   
```
Usage
Run the script with root privileges:
```bash
sudo python3 main.py
```

Customization
To change the injected JavaScript payload, edit this part of the script:

```python
  injection_code = b"<script>REPLACE HERE;</script></div>"

```

Disclaimer
This tool is intended for educational and authorized penetration testing only.
Unauthorized use is illegal and unethical.
