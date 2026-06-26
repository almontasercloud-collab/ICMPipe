# ICMPipe

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)](#)

**ICMPipe** is an ICMP-based client/server communication experiment built with Go and libpcap. Exploring packet-level data transport over raw network protocols.

## Features

- **Raw Socket Interaction:** Directly crafts and parses custom ICMP payloads.
- **Stealth & Diagnostics:** Ideal for advanced network architecture testing, firewall behavior analysis, and environment validation.

---

## Installation

### 1- ICMPipe Server [Windows]

- Download and install npcap [Here](https://npcap.com/).
- Download ICMPipe_Server.exe or pull the full repo if you wish to make changes in the source code.
- Invoke a new cmd with administrator privilage.
- navigate to ICMPipe_Server.exe directory and issue the command: 

```bash
.\ICMPipe-Server.exe
```

- choose the Client-Connected interface and specfiy it's IP address:

```bash
For example:  .\ICMPipe-Server.exe 1 172.16.2.5
```

- you shoud see a message:

```bash
"Listening on interface [1] [interface name] for ICMP Echo Requests from 172.16.2.5"
```

### 2- ICMPipe Client [Linux]

- Install golang:

```bash
sudo apt install golang -y
```
- Install libpcap:

```bash
apt install libpcap-dev
```

- Download **./client/icmpipe_client.go** from this repo:

```bash
wget https://raw.githubusercontent.com/user/repo/main/client/icmpipe_client.go
```

- navigate to icmpipe_client.go and initiate go:

```bash
go mod init icmpipe_client.go
```
- use tidy to download dependancies:

```bash
go mod tidy
```

- Build ICMPipe Executable:

```bash
go build -o ICMPipe icmpope_client.go
```

- Move the executable to your system bin and adjust privilages: (optinal)(recommended)

```bash
sudo mv ICMPipe /usr/local/bin && sudo chmod -x /usr/local/bin/ICMPipe
```
- Issue the command **ICMPipe** to see command usage for example: 

```bash
ICMPipe -p "full path of the file to be pulled using ICMP" -i "Interface Name eg: eth0" -ip "ICMPipe Server IP" -O "output file path" 
```