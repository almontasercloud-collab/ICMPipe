package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {

	if len(os.Args) != 5 {
		fmt.Println("Usage: ICMPipe <interface> <server_ip> <file_path> <output_file>")
		return
	}

	ifaceName := os.Args[1]
	serverIP := os.Args[2]
	filePath := os.Args[3]
	output := os.Args[4]

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface error: %v", err)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("ICMP socket error: %v", err)
	}
	defer conn.Close()

	dst := &net.IPAddr{IP: net.ParseIP(serverIP)}

	fmt.Printf("[+] Using interface: %s (%d)\n", iface.Name, iface.Index)

	// =========================
	// PHASE 1: FR (BASE64 ENCODED)
	// =========================

	fr := base64.StdEncoding.EncodeToString([]byte("FR" + filePath))
	sendICMP(conn, dst, iface, []byte(fr))

	buf := make([]byte, 4096)

	var fileSize int
	found := false

	fmt.Println("[*] Waiting for FA...")

	for !found {

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo := msg.Body.(*icmp.Echo)
		data := string(echo.Data)

		// debug
		fmt.Println("[RX RAW]:", data)

		// ignore FR dummy reply
		if strings.HasPrefix(data, "FR") {
			continue
		}

		// =========================
		// FIXED FA PARSING
		// =========================
		if strings.Contains(data, "FA") {

			start := strings.Index(data, "FA")
			end := strings.LastIndex(data, "FA")

			if start == -1 || end <= start {
				continue
			}

			raw := data[start+2 : end]

			size, err := strconv.Atoi(raw)
			if err != nil {
				fmt.Println("[!] FA parse error:", raw)
				continue
			}

			fileSize = size
			found = true

			fmt.Printf("[+] FA received. File size: %d bytes\n", fileSize)
		}
	}

	// =========================
	// PHASE 2: FP (BASE64 ENCODED)
	// =========================

	fp := base64.StdEncoding.EncodeToString([]byte("FP" + filePath))
	sendICMP(conn, dst, iface, []byte(fp))

	fmt.Println("[*] FP sent, receiving FD...")

	var (
		dataStream string
		total      int
		chunks     int
	)

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	for total < fileSize {

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo := msg.Body.(*icmp.Echo)
		data := string(echo.Data)

		// debug
		fmt.Println("[RX]:", data)

		// ignore FP dummy reply
		if strings.HasPrefix(data, "FP") {
			continue
		}

		// =========================
		// FD HANDLING
		// =========================
		if strings.HasPrefix(data, "FD") {

			chunk := strings.TrimPrefix(data, "FD")
			chunk = strings.TrimRight(chunk, "\x00")

			dataStream += chunk
			chunks++

			total = len(dataStream)

			fmt.Printf("[+] Chunk %d | %d/%d bytes\n", chunks, total, fileSize)
		}
	}

	// =========================
	// FINAL DECODE
	// =========================

	decoded, err := base64.StdEncoding.DecodeString(dataStream)
	if err != nil {
		log.Fatalf("Base64 decode failed: %v", err)
	}

	err = os.WriteFile(output, decoded, 0644)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	fmt.Println("[+] File written to:", output)
}

// =========================
// ICMP SEND FUNCTION
// =========================

func sendICMP(conn *icmp.PacketConn, dst *net.IPAddr, iface *net.Interface, payload []byte) {

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: payload,
		},
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		log.Fatalf("Marshal error: %v", err)
	}

	pconn := conn.IPv4PacketConn()

	err = pconn.SetControlMessage(ipv4.FlagInterface, true)
	if err != nil {
		log.Fatalf("ControlMessage error: %v", err)
	}

	_, err = pconn.WriteTo(b, &ipv4.ControlMessage{
		IfIndex: iface.Index,
	}, dst)

	if err != nil {
		log.Fatalf("ICMP send failed: %v", err)
	}
}
