package main

import (
	"fmt"
	"os"

	"github.com/dreadl0ck/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	tlsHandshakeRecord = 22
)

func detectTLS(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	tlsVersion := tlsx.Version(data[1])<<8 | tlsx.Version(data[2])

	if data[0] != tlsHandshakeRecord {
		return false
	}

	switch tlsVersion {
	case tlsx.VerSSL30, tlsx.VerTLS10, tlsx.VerTLS11, tlsx.VerTLS12, tlsx.VerTLS13:
		return true
	default:
		return false
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: tlsflow <filename> <port>")
		os.Exit(1)
	}

	filename := os.Args[1]
	port := os.Args[2]

	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter("tcp port " + port)
	if err != nil {
		panic(err)
	}

	defer handle.Close()

	var packetCount int
	var clientHello bool
	var serverHello bool
	var mTLS bool

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		payload := packet.TransportLayer().LayerPayload()
		if len(payload) > 0 {
			packetCount++
			flow := packet.TransportLayer().TransportFlow()
			isTLS := detectTLS(payload)
			println(flow.String(), isTLS)

			if isTLS && packetCount == 1 && flow.Dst().String() == port {
				clientHelloMessage := tlsx.GetClientHello(packet)
				if clientHelloMessage != nil {
					clientHello = true
					println("=== ClientHello detected ===")
					println(clientHelloMessage.String())
				}
			}

			if isTLS && packetCount == 2 && flow.Src().String() == port {
				serverHelloMessage := tlsx.GetServerHello(packet)
				if serverHelloMessage != nil {
					serverHello = true
					println("=== ServerHello detected ===")
					println(serverHelloMessage.String())
				}
			}

			// Client Certificate message
			if isTLS && clientHello && serverHello && packetCount == 3 {
				mTLS = true
				println("mTLS detected")

				clientHelloMessage := tlsx.GetClientHello(packet)
				if clientHelloMessage != nil {
					clientHello = true
					println("=== ClientHello detected with ===")
					println(clientHelloMessage.String())
				}
			}
		}
	}

	if serverHello && clientHello {
		fmt.Printf("TLS (mTLS=%t) connection detected\n", mTLS)
		os.Exit(0)
	} else {
		fmt.Println("No TLS connection detected")
		os.Exit(1)
	}
}
