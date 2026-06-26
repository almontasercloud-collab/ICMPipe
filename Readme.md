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

## Installation

## ICMPipe Server [Windows]

1- Download and install npcap [Here](https://npcap.com/)
2- Download ICMPipe_Server.exe or pull the repo of you wish to make changes in the source code.
3- Invoke a new cmd with administrator privilage.
4- navigate to ICMPipe_Server.exe directory and issue the command: 

```bash
.\ICMPipe-Server.exe
```

5- choose the client connected interface and specfiy it's IP address:

```bash
For example:  .\ICMPipe-Server.exe 1 172.16.2.5
```

you shoud see a message "Listening on interface [1] [interface name] for ICMP Echo Requests from 172.16.2.5"


## ICMPipe Server [Linux]

1- First you need to Install required golang kit. 

```bash
sudo apt install golang -y
```

```bash
apt install libpcap-dev
```

```bash
cd client
```

```bash
go mod init icmpipe_client.go
```

```bash
go mod tidy
```

```bash
go build -o ICMPipe icmpope_client.go
```

```bash
sudo mv ICMPipe /usr/local/bin && sudo chmod -x /usr/local/bin/ICMPipe
```

```bash
ICMPipe -p "full path of the file to be pulled using ICMP" -i "Interface Name eg: eth0" -ip "ICMPipe Server IP" -O "output file path" 
```