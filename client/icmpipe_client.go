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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var fileSize int

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

	// Open interface for sniffing
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening interface: %v", err)
	}
	defer handle.Close()

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("icmp error: %v", err)
	}

	defer conn.Close()

	dst := &net.IPAddr{
		IP: net.ParseIP(*serverIP),
	}

	// send file request

	fr := base64.StdEncoding.EncodeToString(
		[]byte("FR" + *filePath),
	)

	send(conn, dst, []byte(fr))

	fmt.Println("Waiting for FA...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	file, err := os.Create(*output)

	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	for packet := range packetSource.Packets() {

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		if ipLayer == nil || icmpLayer == nil {
			continue
		}

		ip := ipLayer.(*layers.IPv4)

		if ip.SrcIP.String() != *serverIP {
			continue
		}

		icmpPacket := icmpLayer.(*layers.ICMPv4)

		rawBytes := string(icmpPacket.Payload)
		decodedBytes, err := base64.StdEncoding.DecodeString(
			string(icmpPacket.Payload),
		)

		if err != nil {
			continue
		}

		data := string(decodedBytes)

		switch {
		// Server sends FA with size
		case icmpPacket.TypeCode.Type() == layers.ICMPv4TypeEchoRequest &&
			strings.HasPrefix(data, "FA"):

			first := 2

			second := strings.Index(data[first:], "FA")

			if second == -1 {
				continue
			}

			second += first

			rawSize := data[first:second]

			fileSize, err = strconv.Atoi(rawSize)

			if err != nil {
				continue
			}

			fmt.Println("File size:", fileSize)
			// START OF PHASE 2
			//Send file pull request to server
			fp := base64.StdEncoding.EncodeToString(
				[]byte("FP" + *filePath))

			send(conn, dst, []byte(fp))

		// File data chunks

		case icmpPacket.TypeCode.Type() == layers.ICMPv4TypeEchoRequest &&
			strings.HasPrefix(rawBytes, "FD"):

			chunk := data[2:]

			raw, _ := base64.StdEncoding.DecodeString(chunk)

			file.Write(raw)

			fmt.Println("received chunk:",
				len(raw),
				"bytes",
			)

		}

	}

}

func listInterfaces() {
	fmt.Println("Available network interfaces:")

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("cannot list interfaces: %v", err)
	}

	for _, iface := range interfaces {
		fmt.Printf("\nID: %d\n", iface.Index)
		fmt.Printf("Name: %s\n", iface.Name)
		fmt.Printf("MAC: %s\n", iface.HardwareAddr)

		addrs, _ := iface.Addrs()

		for _, addr := range addrs {
			fmt.Printf("IP: %s\n", addr.String())
		}
	}
}

func send(conn *icmp.PacketConn, dst *net.IPAddr, payload []byte) {

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: payload,
		},
	}

	bytes, err := msg.Marshal(nil)

	if err != nil {
		log.Println(err)
		return
	}

	_, err = conn.WriteTo(bytes, dst)

	if err != nil {
		log.Println("send error:", err)
	}

}
