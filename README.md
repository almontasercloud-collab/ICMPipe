# ICMPipe

ICMPipe is an experimental Go client/server that transports application data over ICMP using libpcap. Intended for research and learning — not for production use.

---

# Prerequisites

- Go (1.20+ recommended)
- libpcap development libraries (e.g., `libpcap-dev` or Homebrew `libpcap`)
- Elevated privileges to capture/inject packets (root or CAP_NET_RAW/CAP_NET_ADMIN)
- Run only in controlled/test networks with permission

---

# Documentation

Full documentation, usage examples, and design notes are available on my blog:

 [**ICMPipe**](https://almontaserbabiker.com/posts/ICMPipe/)

