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

	fmt.Printf("Using interface: %s (%d)\n", iface.Name, iface.Index)

	// =========================
	// PHASE 1: FILE REQUEST (FR)
	// =========================

	frPayload := []byte("FR" + filePath)

	sendICMP(conn, dst, iface, frPayload)

	buf := make([]byte, 1500)
	var fileSize int
	found := false

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	for !found {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("Timeout waiting FA")
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

		if strings.HasPrefix(data, "FR") {
			fmt.Println(" -> FR Dummy reply received")
			continue
		}

		if strings.HasPrefix(data, "FA") {
			// extract file size
			raw := strings.TrimSuffix(strings.TrimPrefix(data, "FA"), "FA")
			fileSize, _ = strconv.Atoi(raw)

			fmt.Printf(" -> File found. Size: %d bytes\n", fileSize)
			found = true
		}
	}

	// =========================
	// PHASE 2: FILE PULL (FP)
	// =========================

	fpPayload := []byte("FP" + filePath)
	sendICMP(conn, dst, iface, fpPayload)

	fmt.Println(" -> Sent FP request")

	var (
		receivedData string
		totalSize    int
		chunkCount   int
	)

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	for totalSize < fileSize {

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("Timeout receiving FD chunks")
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

		// ignore FP dummy reply
		if strings.HasPrefix(data, "FP") {
			fmt.Println(" -> FP dummy reply received")
			continue
		}

		if strings.HasPrefix(data, "FD") {

			chunk := strings.TrimPrefix(data, "FD")
			chunk = strings.TrimRight(chunk, "\x00")

			receivedData += chunk
			chunkCount++

			fmt.Printf(" -> Received chunk %d | total: %d bytes\n", chunkCount, len(receivedData))

			totalSize = len(receivedData)
		}
	}

	// =========================
	// FINAL DECODE + WRITE
	// =========================

	decoded, err := base64.StdEncoding.DecodeString(receivedData)
	if err != nil {
		log.Fatalf("Base64 decode failed: %v", err)
	}

	err = os.WriteFile(output, decoded, 0644)
	if err != nil {
		log.Fatalf("Write file failed: %v", err)
	}

	fmt.Println(" -> File written to:", output)
}

// =========================
// ICMP SENDER (MATCH SERVER STYLE)
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
		log.Fatalf("Send ICMP failed: %v", err)
	}
}
