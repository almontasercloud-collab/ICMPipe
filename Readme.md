# ICMPipe

A proof-of-concept implementation demonstrating a custom communication algorithm over ICMP-based traffic patterns.

## Overview

ICMPipe is an experimental ICMP-based client/server communication system built with Go and libpcap. This project validates the feasibility of using raw network protocols for data transport by implementing packet-level communication over ICMP.

**Note:** This is an intentionally minimal, experimental codebase designed to demonstrate functional viability in real network environments. It is not production-ready.


## Technical Stack

- **Language:** Go
- **Network Layer:** libpcap (packet capture and injection)
- **Protocol:** ICMP (Internet Control Message Protocol)

## Getting Started

### Prerequisites

- Go 1.16+
- libpcap library and development headers
- This demo code can be built for both windows and linux enviroments. however, for bellow tests **use windows as a server and linux as client**. 

### 1- ICMPipe Server [Windows]

- Download and install npcap [Here](https://npcap.com/).

- Clone the full repository if you want to modify the source code and rebuild ICMPipe server: (**optional**, only required for rebuilding) 

```bash
git clone https://github.com/almontasercloud-collab/ICMPipe.git
```


- Download **ICMPipe_Server.exe**:

```bash
curl -O https://raw.githubusercontent.com/almontasercloud-collab/ICMPipe/main/client/icmpipe_client.go
```

- Run Command Prompt with Administrator privileges.
- navigate to ICMPipe_Server.exe directory and issue bellow command to check host devices and command usage: 

```bash
ICMPipe-Server.exe
```

- (Example) Select the interface and client IP address:

```bash
ICMPipe-Server.exe 1 172.16.2.5
```

- Expected output:

```bash
Listening on interface [1] [interface name] for ICMP Echo Requests from 172.16.2.5
```

### 2- ICMPipe Client [Linux]

- Install golang: (**optional**, only required for rebuilding):

```bash
sudo apt install golang -y
```
- Install libpcap Development Package:

```bash
apt install libpcap-dev
```

- Download **ICMPipe_Client** from this repo:

```bash
wget https://raw.githubusercontent.com/almontasercloud-collab/ICMPipe/main/client/ICMPipe-Client
```

- or clone the full repository if you want to modify the source code and rebuild ICMPipe server: (**optional**, only required for rebuilding):

```bash
git clone https://github.com/almontasercloud-collab/ICMPipe.git
```

- Make the Binary Executable

```bash
sudo chmod 775 ./ICMPipe-Client
```

- Display command usage:

```bash
sudo ./ICMPipe-Client
```
- **(Example)** Select the file, interface, server IP and output path: (change based on your setup)

```bash
sudo ICMPipe-Client -p "C:\Users\Administrator\Documents\test.txt" -i eth0 -ip 172.16.2.10 -O ./loot.txt
```
### 3- Result: 

- The runtime logs now show the transfer workflow clearly, including transfer initiation, file parameters, and data chunk exchanges on both the client and server terminals. Additionally, when using a packet analysis tool (e.g., Wireshark) during the exchange, the algorithm execution steps can be observed directly as they are translated into network packets and transfer operations.

## What's Next: 
#### The implementation acts as a reference execution layer for the algorithm. It handles packet capture, encoding/decoding, and transport simulation using ICMP, but does not represent the final architecture or optimized design. **Let's agree that it's a proof that this method actually works !**

### Engineering Requirements for a Full Implementation: 
1. **Remove `libpcap` dependency**
   - Replace external packet capture dependency with lower-level packet processing mechanisms and OS-native networking APIs.
   - Improve portability, control, and integration with the underlying operating system.

2. **Modular refactoring**
   - Refactor repeated logic into structured, reusable, and testable components.
   - Improve maintainability and prepare the codebase for future expansion.

3. **Introduce a structured packet-processing pipeline**
   - Separate packet creation, parsing, validation, processing, and response handling into dedicated stages.
   - Establish a cleaner internal architecture for protocol operations.

4. **Improve protocol robustness and error handling**
   - Enhance state management, validation, recovery mechanisms, and failure handling.
   - Improve reliability during different communication scenarios.

5. **Expand channel functionality**
   - Extend beyond basic file transfer capabilities.
   - Introduce structured operations such as remote file system navigation and controlled channel interactions.

6. **Improve packet size management**
   - Implement better packet sizing control for both Phase 1 and Phase 2 communication stages.
   - Optimize transfer reliability and efficiency.

7. **Enhance transfer lifecycle management**
   - Improve handling and control of all main protocol stages:
     - `FR` — File Request
     - `FA` — File Acknowledgement
     - `FP` — File Preparation / Processing
     - `FD` — File Data Transfer
   - Provide clearer state transitions and better communication flow control.
