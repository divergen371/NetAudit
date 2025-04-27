package network

import (
	"log"
	"net"
)

// expandCIDRはCIDR表記からIPアドレスのスライスを返す
func ExpandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("Invalid CIDR: %v", err)
	}
	var ips []string
	for curIP := ip.Mask(ipnet.Mask); ipnet.Contains(curIP); IncrementIP(curIP) {
		ips = append(ips, curIP.String())
	}
	if len(ips) > 0 {
		ips = ips[1:]
	}
	if len(ips) > 0 {
		ips = ips[:len(ips)-1]
	}
	return ips
}

// IncrementIPはIPアドレスをインクリメントする
func IncrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
