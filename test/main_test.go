package main

import (
	"net"
	"testing"

	"github.com/divergen371/NetAudit/internal/network"
	"github.com/divergen371/NetAudit/internal/scanner"
)

// ExpandCIDRのテスト
func TestExpandCIDR(t *testing.T) {
	cidr := "192.168.1.0/30"
	ips := network.ExpandCIDR(cidr)
	expected := []string{"192.168.1.1", "192.168.1.2"}
	if len(ips) != len(expected) {
		t.Fatalf("want %d IPs, got %d", len(expected), len(ips))
	}
	for i, ip := range ips {
		if ip != expected[i] {
			t.Errorf("want %s, got %s", expected[i], ip)
		}
	}
}

// IncrementIPのテスト
func TestIncrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	network.IncrementIP(ip)
	if ip.String() != "192.168.1.2" {
		t.Errorf("want 192.168.1.2, got %s", ip.String())
	}
}

// GetServiceNameのテスト
func TestGetServiceName(t *testing.T) {
	if name := scanner.GetServiceName("tcp", 22); name != "SSH" {
		t.Errorf("want SSH, got %s", name)
	}
	if name := scanner.GetServiceName("udp", 53); name != "DNS" {
		t.Errorf("want DNS, got %s", name)
	}
	if name := scanner.GetServiceName("tcp", 9999); name != "" {
		t.Errorf("want empty, got %s", name)
	}
}

// CreateUDPProbeのテスト
func TestCreateUDPProbe(t *testing.T) {
	dns := scanner.CreateUDPProbe(53)
	if len(dns) != 12 {
		t.Errorf("want 12 bytes for DNS probe, got %d", len(dns))
	}
	ntp := scanner.CreateUDPProbe(123)
	if len(ntp) != 12 {
		t.Errorf("want 12 bytes for NTP probe, got %d", len(ntp))
	}
	snmp := scanner.CreateUDPProbe(161)
	if len(snmp) != 13 {
		t.Errorf("want 13 bytes for SNMP probe, got %d", len(snmp))
	}
	other := scanner.CreateUDPProbe(9999)
	if string(other) != "HELLO" {
		t.Errorf("want HELLO, got %s", string(other))
	}
}
