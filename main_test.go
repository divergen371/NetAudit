package main

import (
	"net"
	"testing"
)

// expandCIDRのテスト
func TestExpandCIDR(t *testing.T) {
	cidr := "192.168.1.0/30"
	ips := expandCIDR(cidr)
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

// incrementIPのテスト
func TestIncrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	incrementIP(ip)
	if ip.String() != "192.168.1.2" {
		t.Errorf("want 192.168.1.2, got %s", ip.String())
	}
}

// getServiceNameのテスト
func TestGetServiceName(t *testing.T) {
	if name := getServiceName("tcp", 22); name != "SSH" {
		t.Errorf("want SSH, got %s", name)
	}
	if name := getServiceName("udp", 53); name != "DNS" {
		t.Errorf("want DNS, got %s", name)
	}
	if name := getServiceName("tcp", 9999); name != "" {
		t.Errorf("want empty, got %s", name)
	}
}

// createUDPProbeのテスト
func TestCreateUDPProbe(t *testing.T) {
	dns := createUDPProbe(53)
	if len(dns) != 12 {
		t.Errorf("want 12 bytes for DNS probe, got %d", len(dns))
	}
	ntp := createUDPProbe(123)
	if len(ntp) != 12 {
		t.Errorf("want 12 bytes for NTP probe, got %d", len(ntp))
	}
	snmp := createUDPProbe(161)
	if len(snmp) != 13 {
		t.Errorf("want 13 bytes for SNMP probe, got %d", len(snmp))
	}
	other := createUDPProbe(9999)
	if string(other) != "HELLO" {
		t.Errorf("want HELLO, got %s", string(other))
	}
}
