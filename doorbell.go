package main

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device       string = "en0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 5 * time.Second
	handle       *pcap.Handle
)

func main() {
	// Open device
	fmt.Print("Opening device\n")
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Print("Packet source connected\n")

	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arpPacket, _ := arpLayer.(*layers.ARP)
			fmt.Println("Source HW: ", arpPacket.SourceHwAddress)
			fmt.Println("Dst HW: ", arpPacket.DstHwAddress)
			if bytes.Equal(arpPacket.SourceHwAddress, []byte{80, 245, 218, 142, 193, 250}) {
				fmt.Println("FOUND THE SODDING DASH DONGLE")
			}
		}
	}
}
