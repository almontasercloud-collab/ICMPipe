package main

import (
	"encoding/base64"
	"flag"
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

	filePath := flag.String("p", "", "file path")
	ifaceName := flag.String("i", "", "interface")
	serverIP := flag.String("ip", "", "server ip")
	output := flag.String("O", "", "output file")

	flag.Parse()

	if *filePath == "" || *ifaceName == "" || *serverIP == "" || *output == "" {
		fmt.Println("Usage: ICMPipe -p <file> -i <iface> -ip <server> -O <out>")
		os.Exit(1)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("iface error: %v", err)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("icmp error: %v", err)
	}
	defer conn.Close()

	dst := &net.IPAddr{IP: net.ParseIP(*serverIP)}

	buf := make([]byte, 4096)

	// =========================
	// PHASE 1: FR
	// =========================

	frPayload := base64.StdEncoding.EncodeToString([]byte("FR" + *filePath))
	send(conn, dst, iface, []byte(frPayload))

	var fileSize int
	found := false

	fmt.Println("Waiting FA...")

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

		decodedBytes, err := base64.StdEncoding.DecodeString(string(echo.Data))
		if err != nil {
			continue
		}

		data := string(decodedBytes)

		fmt.Println("Directory:", data)

		switch {

		case msg.Type == ipv4.ICMPTypeEchoReply &&
			strings.HasPrefix(data, "FR"):

			// This is the server dummy reply
			fmt.Println("FR dummy reply received")

		case msg.Type == ipv4.ICMPTypeEcho &&
			strings.HasPrefix(data, "FA"):

			// This is the real server request containing file size

			start := strings.Index(data, "FA")
			end := strings.LastIndex(data, "FA")

			if start == -1 || end <= start {
				continue
			}

			raw := data[start+2 : end]

			size, err := strconv.Atoi(raw)
			if err != nil {
				continue
			}

			fileSize = size
			found = true

			fmt.Println("FA received size:", fileSize)
		}
	}

	// =========================
	// PHASE 2: FP
	// =========================

	fpPayload := base64.StdEncoding.EncodeToString([]byte("FP" + *filePath))
	send(conn, dst, iface, []byte(fpPayload))

	fmt.Println("FP sent")

	var (
		stream string
		total  int
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

		decodedBytes, err := base64.StdEncoding.DecodeString(string(echo.Data))
		if err != nil {
			continue
		}

		data := string(decodedBytes)

		fmt.Println("RX:", data)

		switch {

		case strings.HasPrefix(data, "FP"):
			fmt.Println("FP dummy reply")

		case strings.HasPrefix(data, "FD"):

			chunk := strings.TrimPrefix(data, "FD")

			stream += chunk
			total = len(stream)

			fmt.Printf("FD chunk received | %d/%d\n", total, fileSize)
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(stream)
	if err != nil {
		log.Fatalf("decode error: %v", err)
	}

	os.WriteFile(*output, decoded, 0644)

	fmt.Println("DONE:", *output)
}

// =========================
// SEND (server-like helper)
// =========================

func send(conn *icmp.PacketConn, dst *net.IPAddr, iface *net.Interface, payload []byte) {

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: payload,
		},
	}

	b, _ := msg.Marshal(nil)

	pconn := conn.IPv4PacketConn()
	pconn.SetControlMessage(ipv4.FlagInterface, true)

	pconn.WriteTo(b, &ipv4.ControlMessage{
		IfIndex: iface.Index,
	}, dst)
}
