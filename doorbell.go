package main

import (
	"bytes"
	"flag"
	"fmt"
	twilio "github.com/carlosdp/twiliogo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"time"
)

var (
	device       string = "en0"
	snapshot_len int32  = 512
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 1 * time.Second
	handle       *pcap.Handle
)

var twilio_sid = flag.String("twilio_sid", os.Getenv("TWILIO_SID"), "Twilio SID")
var twilio_token = flag.String("twilio_token", os.Getenv("TWILIO_TOKEN"), "Twilio Auth Token")
var to_number = flag.String("to_number", os.Getenv("TO_NUMBER"), "Number to message")
var from_number = flag.String("from_number", os.Getenv("FROM_NUMBER"), "Number to text from (as defined in Twilio)")
var dash_mac = flag.String("dash_mac", os.Getenv("DASH_MAC"), "MAC Address of Amazon Dash button")
var minimum_interval = flag.Int("min_interval", 10, "Minimum interval between button presses (seconds)")

var last_pressed int64 = 0

func main() {
	flag.Parse()

	if *twilio_sid == "" || *twilio_sid == "" || *to_number == "" || *from_number == "" {
		fmt.Fprintf(os.Stderr, "Twilio tokens or numbers not defined\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *dash_mac == "" {
		fmt.Fprintf(os.Stderr, "Dash button MAC address is mandatory\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	listen()
}

func listen() {
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	dashHwAddress, err := net.ParseMAC(*dash_mac)

	if err != nil {
		//TODO: use logging package
		fmt.Fprintf(os.Stderr, "Error processing MAC address")
		os.Exit(1)
	}

	fmt.Printf("Filtering for MAC %s\n", dashHwAddress)

	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arpPacket, _ := arpLayer.(*layers.ARP)
			if bytes.Equal(arpPacket.SourceHwAddress, dashHwAddress) {
				fmt.Printf("ARP request seen from %s\n", dashHwAddress)

				difference := time.Now().Unix() - last_pressed

				if difference >= int64(*minimum_interval) {
					fmt.Printf("Difference was %d -- triggering\n", difference)
					last_pressed = time.Now().Unix()
					go trigger()
				} else {
					fmt.Printf("Difference was %d, too short -- not triggering\n", difference)
				}
			}
		}
	}
}

func trigger() {
	fmt.Println("Triggered -- sending text message")

	client := twilio.NewClient(*twilio_sid, *twilio_token)
	body := fmt.Sprintf("Dash button pressed at %s", time.Now())

	message, err := twilio.NewMessage(client, *from_number, *to_number, twilio.Body(body))
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Twilio Response: %s\n", message.Status)
	}
	fmt.Println()
}
