package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"os"
	"time"
)

func main() {
	// Arguments
	dir := flag.String("p", "", "directory string to encode")
	ifaceName := flag.String("i", "", "network interface")
	dstIP := flag.String("ip", "", "destination IP")
	output := flag.String("O", "", "output file path")
	flag.Parse()

	if *dir == "" || *ifaceName == "" || *dstIP == "" || *output == "" {
		fmt.Println("Usage: pring -p <directory> -i <interface> -ip <ip> -O <output_file>")
		os.Exit(1)
	}

	// Base64 encode directory
	encodedPayload := base64.StdEncoding.EncodeToString([]byte(*dir))

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		panic(err)
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		panic(err)
	}
	defer c.Close()

	// Bind to interface
	pconn := ipv4.NewPacketConn(c)
	if err := pconn.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		panic(err)
	}

	dst := &net.IPAddr{IP: net.ParseIP(*dstIP)}

	// ICMP Echo
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(encodedPayload),
		},
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		panic(err)
	}

	// Send single ping
	_, err = pconn.WriteTo(b, &ipv4.ControlMessage{
		IfIndex: iface.Index,
	}, dst)
	if err != nil {
		panic(err)
	}

	// Listen for replies
	var encodedData []byte
	buf := make([]byte, 1500)

	deadline := time.Now().Add(7 * time.Second)
	_ = c.SetReadDeadline(deadline)

	for {
		n, _, peer, err := c.ReadFrom(buf)
		if err != nil {
			break // timeout
		}

		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		if rm.Type == ipv4.ICMPTypeEchoReply {
			if body, ok := rm.Body.(*icmp.Echo); ok {
				fmt.Println("Reply from:", peer.String())
				encodedData = append(encodedData, body.Data...)
			}
		}
	}

	// Decode final data
	decoded, err := base64.StdEncoding.DecodeString(string(encodedData))
	if err != nil {
		panic(err)
	}

	// Write output
	err = os.WriteFile(*output, decoded, 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("File written to:", *output)
}
