# ICMPipe

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)](#)

**ICMPipe** is an ICMP-based client/server communication experiment built with Go and libpcap. Exploring packet-level data transport over raw network protocols.

## Features

- **Raw Socket Interaction:** Directly crafts and parses custom ICMP payloads.
- **Data Encapsulation:** Pipes standard input stream (`stdin`) or structured data directly through ICMP Echo Request/Reply mechanisms.
- **Stealth & Diagnostics:** Ideal for advanced network architecture testing, firewall behavior analysis, and environment validation.
- **Cross-Platform Support:** Compatible across Unix-like systems (Linux, macOS).

---

## Client Installation

Clone the repository:

```bash
git clone https://github.com/almontasercloud-collab/ICMPipe.git
```

The client code is writen for Linux-based Systems , First you need to Install required golang kit. 

```bash
sudo apt install golang -y
```

