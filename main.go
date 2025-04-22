package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/semaphore"
)

var (
	scanType    string
	startPort   int
	endPort     int
	targetIP    string
	scanSpeed   int
	protocol    string
	timeout     time.Duration
	workerCount int64
	verbose     bool
)

func main() {
	// コマンドライン引数の解析
	flag.StringVar(&targetIP, "ip", "", "スキャン対象のIPアドレスまたはCIDR範囲（例: 192.168.1.1 または 192.168.1.0/24）")
	flag.IntVar(&startPort, "start", 1, "スキャン開始ポート")
	flag.IntVar(&endPort, "end", 1000, "スキャン終了ポート")
	flag.StringVar(&scanType, "type", "connect", "スキャンタイプ (connect, syn, udp)")
	flag.StringVar(&protocol, "proto", "tcp", "プロトコル (tcp, udp, both)")
	flag.IntVar(&scanSpeed, "speed", 2, "スキャンスピード (1=遅い, 2=普通, 3=速い)")
	flag.BoolVar(&verbose, "v", false, "詳細出力")
	flag.Parse()

	// スキャンスピードに基づいて設定を調整
	switch scanSpeed {
	case 1:
		timeout = 2 * time.Second
		workerCount = 10
	case 2:
		timeout = 1 * time.Second
		workerCount = 50
	case 3:
		timeout = 500 * time.Millisecond
		workerCount = 100
	default:
		fmt.Println("無効なスピード設定です。デフォルト(2)を使用します")
		timeout = 1 * time.Second
		workerCount = 50
	}

	// 入力検証
	if targetIP == "" {
		fmt.Println("使用法: portscanner -ip [IPアドレス/CIDR] -start [開始ポート] -end [終了ポート] -type [connect/syn/udp] -proto [tcp/udp/both] -speed [1-3]")
		os.Exit(1)
	}

	// CIDRチェック (ネットワークスキャン)
	if strings.Contains(targetIP, "/") {
		hosts := expandCIDR(targetIP)
		fmt.Printf("ネットワーク %s 内のホストを探索中...\n", targetIP)
		discoveredHosts := discoverHosts(hosts)

		if len(discoveredHosts) == 0 {
			fmt.Println("アクティブなホストが見つかりませんでした")
			return
		}

		fmt.Printf("%d台のアクティブホストを発見しました\n", len(discoveredHosts))
		for _, host := range discoveredHosts {
			fmt.Printf("ホスト %s のポートスキャンを開始します\n", host)
			scanPorts(host)
			fmt.Println()
		}
	} else {
		// 単一ホストスキャン
		scanPorts(targetIP)
	}
}

func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("Invalid CIDR: %v", err)
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 0 {
		ips = ips[1:]
	}

	if len(ips) > 0 {
		ips = ips[:len(ips)-1]
	}
	return ips
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func discoverHosts(hosts []string) []string {
	var discoveredHosts []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	sem := semaphore.NewWeighted(workerCount)
	ctx := context.Background()

	for _, host := range hosts {
		wg.Add(1)
		sem.Acquire(ctx, 1)
		go func(ip string) {
			defer wg.Done()
			defer sem.Release(1)

			alive := pingHost(ip)
			if !alive && isLinux() {
				alive = arpScan(ip)
			}
			if alive {
				mu.Lock()
				discoveredHosts = append(discoveredHosts, ip)
				mu.Unlock()
				if verbose {
					fmt.Printf("Host discovered: %s\n", ip)
				}
			}
		}(host)
	}
	wg.Wait()
	return discoveredHosts
}

func pingHost(ip string) bool {
	conn, err := icmp.ListenPacket("ipv4:icmp", "0.0.0.0")
	if err != nil {
		if verbose {
			log.Printf("ICMP Listen error: %v", err)
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

	if _, err := conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(ip)}); err != nil {
		return false
	}

	rb := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := conn.ReadFrom(rb)
	if err != nil {
		return false
	}

	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		return false
	}

	if rm.Type == ipv4.ICMPTypeEchoReply {
		return true
	}
	return false
}

func arpScan(ip string) bool {
	// 実際のARPスキャンはOSに依存するためここでは簡略化
	// TODO 実装を検討
	if isLinux() {
		return attemptConnect(ip, 22) || attemptConnect(ip, 80) || attemptConnect(ip, 443)
	}
	return false
}

func attemptConnect(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		conn.Close()
		return true
	}
	return false
}

func scanPorts(ip string) {
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(workerCount)
	ctx := context.Background()

	fmt.Printf("Start scan on port %d-%d for %s\n", startPort, endPort, ip)
	startPort := time.Now()
	switch strings.ToLower(protocol) {
	case "tcp":
		scanTCPPorts(ip, &wg, sem, ctx)
	case "udp":
		scanUDPPorts(ip, &wg, sem, ctx)
	case "both":
		scanTCPPorts(ip, &wg, sem, ctx)
		scanUDPPorts(ip, &wg, sem, ctx)
	default:
		fmt.Println("Invalid protocol, will use TCP.")
		scanTCPPorts(ip, &wg, sem, ctx)
	}
	wg.Wait()
	elapsed := time.Since(startPort)
	fmt.Printf("Scan completed in %s\n", elapsed)
}

func scanTCPPorts(ip string, wg *sync.WaitGroup, sem *semaphore.Weighted, ctx context.Context) {
	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem.Acquire(ctx, 1)
		go func(port int) {
			defer wg.Done()
			defer sem.Release(1)
			switch strings.ToLower(scanType) {
			case "connect":
				scanTCPConnect(ip, port)
			case "syn":
				scanTCPSyn(ip, port)
			default:
				scanTCPConnect(ip, port)
			}
		}(port)
	}
}

func scanUDPPorts(ip string, wg *sync.WaitGroup, sem *semaphore.Weighted, ctx context.Context) {
	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem.Acquire(ctx, 1)
		go func(port int) {
			defer wg.Done()
			defer sem.Release(1)
			scanUDP(ip, port)
		}(port)
	}
}

func scanTCPConnect(ip string, port int) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err == nil {
		service := getServiceName("tcp", port)
		fmt.Printf("TCP %d\topen\t%s\n", port, service)
		conn.Close()
	} else if verbose {
		fmt.Printf("TCP %d\tclose\n", port)
	}
}

func scanTCPSyn(ip string, port int) {
	// SYNスキャンにはroot権限とraw socketが必要
	if os.Getuid() != 0 {
		if port == startPort {
			fmt.Println("SYN scan requires root privileges. Connect scan will be used instead.")
		}
		scanTCPConnect(ip, port)
		return
	}

	// TODO SYNスキャンをどうするか？libpcapのライブラリが必要
	// とりあえずConnect Scanを使用
	scanTCPConnect(ip, port)
}

func scanUDP(ip string, port int) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", target, timeout)
	if err == nil {
		if verbose {
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
	conn.SetReadDeadline(time.Now().Add(timeout))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err == nil && n > 0 {
		service := getServiceName("udp", port)
		fmt.Printf("UDP %d\topen\t%s\n", port, service)
	} else if verbose {
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
		// 一般的なプローブ
		return []byte("HELLO")
	}
}

func getServiceName(protocol string, port int) string {
	// OSのservices DBを使用するべきか
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

func isLinux() bool {
	return os.Getenv("OS") != "Windows_NT"
}
