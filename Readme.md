# ICMPipe

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)](#)

**ICMPipe** is an ICMP-based client/server communication experiment built with Go and libpcap. Exploring packet-level data transport over raw network protocols.

---

## Installation

### 1- ICMPipe Server [Windows]

- Download and install npcap [Here](https://npcap.com/).
- Download **ICMPipe_Server.exe** or clone the full repository if you want to modify the source code and rebuild ICMPipe server.
- Run Server with Administrator Privileges.
- navigate to ICMPipe_Server.exe directory and issue the command: 

```bash
.\ICMPipe-Server.exe
```

- Select the interface and client IP address:

```bash
For example:  .\ICMPipe-Server.exe 1 172.16.2.5
```

- Expected output:

```bash
"Listening on interface [1] [interface name] for ICMP Echo Requests from 172.16.2.5"
```

### 2- ICMPipe Client [Linux]

- Install golang:

```bash
sudo apt install golang -y
```
- Install libpcap Development Package:

```bash
apt install libpcap-dev
```

- Download **icmpipe_client.go** from this repo:

```bash
https://github.com/almontasercloud-collab/ICMPipe/blob/main/client/icmpipe_client.go
```

- navigate to directory containing **icmpipe_client.go** file and Initialize Go:

```bash
go mod init icmpipe_client.go
```
- download and configure the required Go dependencies:

```bash
go mod tidy
```

- Build ICMPipe client:

```bash
go build -o ICMPipe icmpope_client.go
```

- Install ICMPipe globally and set execution permissions: (Optinal Recommended)

```bash
sudo mv ICMPipe /usr/local/bin && sudo chmod -x /usr/local/bin/ICMPipe
```
- Display available options:

```bash
ICMPipe
```

## Documentation & Walkthrough

A complete ICMPipe walkthrough, including setup steps and usage examples, is available on my blog:

[ICMPipe Walkthrough](https://almontaserbabiker.com/posts/ICMPipe/)