package test

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/divergen371/NetAudit/internal/config"
	"github.com/divergen371/NetAudit/internal/network"
	"github.com/divergen371/NetAudit/internal/scanner"
)

// --- networkパッケージ ---

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

func TestIncrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	network.IncrementIP(ip)
	if ip.String() != "192.168.1.2" {
		t.Errorf("want 192.168.1.2, got %s", ip.String())
	}
}

func TestDetectLocalOS(t *testing.T) {
	osName := network.DetectLocalOS()
	if osName != runtime.GOOS {
		t.Errorf("DetectLocalOS: want %s, got %s", runtime.GOOS, osName)
	}
}

func TestDetectRemoteOS_Unknown(t *testing.T) {
	osName := network.DetectRemoteOS("10.255.255.254")
	if osName != "unknown" {
		t.Errorf("DetectRemoteOS: want unknown, got %s", osName)
	}
}

// --- scannerパッケージ ---

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

func TestPingHost_Localhost(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOSではICMPテストをスキップします")
	}
	cfg := &scanner.ICMPConfig{Timeout: 1 * time.Second, Verbose: false}
	if !scanner.PingHost("127.0.0.1", cfg) {
		t.Error("PingHost: localhost should be alive")
	}
}

func TestARPScan_InvalidIface(t *testing.T) {
	cfg := &scanner.ARPConfig{IfaceName: "invalid0", Timeout: 1 * time.Second, Verbose: false}
	if scanner.ARPScan("192.0.2.1", cfg) {
		t.Error("ARPScan: should fail with invalid interface")
	}
}

func TestDiscoverHosts_Empty(t *testing.T) {
	cfg := &config.Config{
		Timeout:     1 * time.Second,
		WorkerCount: 2,
		Verbose:     false,
		IfaceName:   "invalid0",
	}
	hosts := []string{"10.255.255.254"}
	found := scanner.DiscoverHosts(hosts, cfg)
	if len(found) != 0 {
		t.Errorf("DiscoverHosts: want 0, got %d", len(found))
	}
}
