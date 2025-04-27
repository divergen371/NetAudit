package scanner

import (
	"context"
	"fmt"
	"io"
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

// PortScannerインターフェースを定義
// io.Writerに出力を書き込む
// internal/scanner/scanner.goに移動しても良い

type PortScanner interface {
	ScanPorts(w io.Writer, ip string, cfg *Config)
}

type RealPortScanner struct{}

func (r *RealPortScanner) ScanPorts(w io.Writer, ip string, cfg *Config) {
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(cfg.WorkerCount)
	ctx := context.Background()
	fmt.Fprintf(w, "Start scan on port %d-%d for %s\n", cfg.StartPort, cfg.EndPort, ip)
	startTime := time.Now()
	switch strings.ToLower(cfg.Protocol) {
	case "tcp":
		scanTCPPorts(w, ip, &wg, sem, ctx, cfg)
	case "udp":
		scanUDPPorts(w, ip, &wg, sem, ctx, cfg)
	case "both":
		scanTCPPorts(w, ip, &wg, sem, ctx, cfg)
		scanUDPPorts(w, ip, &wg, sem, ctx, cfg)
	default:
		fmt.Fprintln(w, "Invalid protocol, will use TCP.")
		scanTCPPorts(w, ip, &wg, sem, ctx, cfg)
	}
	wg.Wait()
	elapsed := time.Since(startTime)
	fmt.Fprintf(w, "Scan completed in %s\n", elapsed)
}

// scanTCPPorts/scanUDPPorts/scanTCPConnect/scanTCPSyn/scanUDP もio.Writerを受け取るように修正
func scanTCPPorts(w io.Writer, ip string, wg *sync.WaitGroup, sem *semaphore.Weighted, ctx context.Context, cfg *Config) {
	for port := cfg.StartPort; port <= cfg.EndPort; port++ {
		wg.Add(1)
		sem.Acquire(ctx, 1)
		go func(port int) {
			defer wg.Done()
			defer sem.Release(1)
			switch strings.ToLower(cfg.ScanType) {
			case "connect":
				scanTCPConnect(w, ip, port, cfg)
			case "syn":
				scanTCPSyn(w, ip, port, cfg)
			default:
				scanTCPConnect(w, ip, port, cfg)
			}
		}(port)
	}
}

func scanUDPPorts(w io.Writer, ip string, wg *sync.WaitGroup, sem *semaphore.Weighted, ctx context.Context, cfg *Config) {
	for port := cfg.StartPort; port <= cfg.EndPort; port++ {
		wg.Add(1)
		sem.Acquire(ctx, 1)
		go func(port int) {
			defer wg.Done()
			defer sem.Release(1)
			scanUDP(w, ip, port, cfg)
		}(port)
	}
}

func scanTCPConnect(w io.Writer, ip string, port int, cfg *Config) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, cfg.Timeout)
	if err == nil {
		service := GetServiceName("tcp", port)
		fmt.Fprintf(w, "TCP %d\topen\t%s\n", port, service)
		conn.Close()
	} else if cfg.Verbose {
		fmt.Fprintf(w, "TCP %d\tclose\n", port)
	}
}

func scanTCPSyn(w io.Writer, ip string, port int, cfg *Config) {
	if port == cfg.StartPort {
		fmt.Fprintln(w, "SYN scan requires root privileges. Connect scan will be used instead.")
	}
	scanTCPConnect(w, ip, port, cfg)
}

func scanUDP(w io.Writer, ip string, port int, cfg *Config) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", target, cfg.Timeout)
	if err == nil {
		if cfg.Verbose {
			fmt.Fprintf(w, "UDP %d\tunreachable\n", port)
		}
		return
	}
	payload := CreateUDPProbe(port)
	_, err = conn.Write(payload)
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err == nil && n > 0 {
		service := GetServiceName("udp", port)
		fmt.Fprintf(w, "UDP %d\topen\t%s\n", port, service)
	} else if cfg.Verbose {
		fmt.Fprintf(w, "UDP %d\tunknown/filtered\n", port)
	}
	conn.Close()
}

func GetServiceName(protocol string, port int) string {
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

func CreateUDPProbe(port int) []byte {
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

// ===== テスト用モック実装 =====
// 任意の出力やエラーを注入できるようにする

type MockPortScanner struct {
	MockOutput string
}

func (m *MockPortScanner) ScanPorts(w io.Writer, ip string, cfg *Config) {
	w.Write([]byte(m.MockOutput))
}
