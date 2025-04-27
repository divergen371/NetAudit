package scanner

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ICMPConfig struct {
	Timeout time.Duration
	Verbose bool
}

func PingHost(targetIP string, cfg *ICMPConfig) bool {
	conn, err := icmp.ListenPacket("ipv4:icmp", "0.0.0.0")
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("ICMP Listen error: %v\n", err)
		}
		return false
	}
	defer conn.Close()
	vm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xFFFF, Seq: 1,
			Data: []byte("PING-PONG:D"),
		},
	}
	wb, err := vm.Marshal(nil)
	if err != nil {
		return false
	}
	_, err = conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(targetIP)})
	if err != nil {
		return false
	}
	rb := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
	n, _, err := conn.ReadFrom(rb)
	if err != nil {
		return false
	}
	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		return false
	}
	return rm.Type == ipv4.ICMPTypeEchoReply
}
