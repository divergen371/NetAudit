package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

type Config struct {
	StartPort   int
	EndPort     int
	ScanType    string
	Protocol    string
	Timeout     time.Duration
	WorkerCount int64
	Verbose     bool
}

func ScanPorts(ip string, cfg *Config) {
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(cfg.WorkerCount)
	ctx := context.Background()
	fmt.Printf("Start scan on port %d-%d for %s\n", cfg.StartPort, cfg.EndPort, ip)
	startTime := time.Now()
	switch strings.ToLower(cfg.Protocol) {
	case "tcp":
		scanTCPPorts(ip, &wg, sem, ctx, cfg)
	case "udp":
		scanUDPPorts(ip, &wg, sem, ctx, cfg)
	case "both":
		scanTCPPorts(ip, &wg, sem, ctx, cfg)
		scanUDPPorts(ip, &wg, sem, ctx, cfg)
	default:
		fmt.Println("Invalid protocol, will use TCP.")
		scanTCPPorts(ip, &wg, sem, ctx, cfg)
	}
	wg.Wait()
	elapsed := time.Since(startTime)
	fmt.Printf("Scan completed in %s\n", elapsed)
}

func scanTCPPorts(ip string, wg *sync.WaitGroup, sem *semaphore.Weighted, ctx context.Context, cfg *Config) {
	for port := cfg.StartPort; port <= cfg.EndPort; port++ {
		wg.Add(1)
		sem.Acquire(ctx, 1)
		go func(port int) {
			defer wg.Done()
			defer sem.Release(1)
			switch strings.ToLower(cfg.ScanType) {
			case "connect":
				scanTCPConnect(ip, port, cfg)
			case "syn":
				scanTCPSyn(ip, port, cfg)
			default:
				scanTCPConnect(ip, port, cfg)
			}
		}(port)
	}
}

func scanUDPPorts(ip string, wg *sync.WaitGroup, sem *semaphore.Weighted, ctx context.Context, cfg *Config) {
	for port := cfg.StartPort; port <= cfg.EndPort; port++ {
		wg.Add(1)
		sem.Acquire(ctx, 1)
		go func(port int) {
			defer wg.Done()
			defer sem.Release(1)
			scanUDP(ip, port, cfg)
		}(port)
	}
}

func scanTCPConnect(ip string, port int, cfg *Config) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, cfg.Timeout)
	if err == nil {
		service := getServiceName("tcp", port)
		fmt.Printf("TCP %d\topen\t%s\n", port, service)
		conn.Close()
	} else if cfg.Verbose {
		fmt.Printf("TCP %d\tclose\n", port)
	}
}

func scanTCPSyn(ip string, port int, cfg *Config) {
	if port == cfg.StartPort {
		fmt.Println("SYN scan requires root privileges. Connect scan will be used instead.")
	}
	scanTCPConnect(ip, port, cfg)
}

func scanUDP(ip string, port int, cfg *Config) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", target, cfg.Timeout)
	if err == nil {
		if cfg.Verbose {
			fmt.Printf("UDP %d\tunreachable\n", port)
		}
		return
	}
	payload := createUDPProbe(port)
	_, err = conn.Write(payload)
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err == nil && n > 0 {
		service := getServiceName("udp", port)
		fmt.Printf("UDP %d\topen\t%s\n", port, service)
	} else if cfg.Verbose {
		fmt.Printf("UDP %d\tunknown/filtered\n", port)
	}
	conn.Close()
}

func createUDPProbe(port int) []byte {
	switch port {
	case 53: // DNS
		return []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 123: // NTP
		return []byte{0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 161: // SNMP
		return []byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63}
	default:
		return []byte("HELLO")
	}
}

func getServiceName(protocol string, port int) string {
	services := map[string]map[int]string{
		"tcp": {
			21:   "FTP",
			22:   "SSH",
			23:   "Telnet",
			25:   "SMTP",
			80:   "HTTP",
			443:  "HTTPS",
			445:  "SMB",
			3306: "MySQL",
			3389: "RDP",
		},
		"udp": {
			53:   "DNS",
			67:   "DHCP",
			123:  "NTP",
			161:  "SNMP",
			1900: "UPnP",
		},
	}
	if serviceMap, ok := services[protocol]; ok {
		if name, ok := serviceMap[port]; ok {
			return name
		}
	}
	return ""
}
