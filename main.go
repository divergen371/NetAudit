package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/semaphore"
)

// Config構造体はCLIオプションとスキャン設定を保持する
// この構造体を使ってグローバル変数を排除し、テストや保守性を向上させる

type Config struct {
	TargetIP    string
	StartPort   int
	EndPort     int
	ScanType    string
	Protocol    string
	ScanSpeed   int
	Verbose     bool
	IfaceName   string
	Timeout     time.Duration
	WorkerCount int64
}

var cfg Config

var rootCmd = &cobra.Command{
	Use:   "portscanner",
	Short: "シンプルなポートスキャナ",
	Long:  "IPアドレスやCIDR範囲を指定してポートスキャンを行うツールです.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := cfg.validate(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		cfg.adjustSettings()
		runScan(&cfg)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfg.TargetIP, "i", "i", "", "スキャン対象のIPアドレスまたはCIDR範囲（例: 192.168.1.1 または 192.168.1.0/24）【必須】")
	rootCmd.PersistentFlags().IntVarP(&cfg.StartPort, "s", "s", 1, "スキャン開始ポート (デフォルト: 1)")
	rootCmd.PersistentFlags().IntVarP(&cfg.EndPort, "e", "e", 1000, "スキャン終了ポート (デフォルト: 1000)")
	rootCmd.PersistentFlags().StringVarP(&cfg.ScanType, "t", "t", "connect", "スキャンタイプ (connect, syn, udp) (デフォルト: connect)")
	rootCmd.PersistentFlags().StringVarP(&cfg.Protocol, "p", "p", "tcp", "プロトコル (tcp, udp, both) (デフォルト: tcp)")
	rootCmd.PersistentFlags().IntVarP(&cfg.ScanSpeed, "S", "S", 2, "スキャンスピード (1=遅い, 2=普通, 3=速い) (デフォルト: 2)")
	rootCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "v", "v", false, "詳細出力を有効化")
	rootCmd.PersistentFlags().StringVarP(&cfg.IfaceName, "I", "I", "", "利用するネットワークインターフェース名（例: eth0, en0 など）")

	rootCmd.MarkPersistentFlagRequired("i")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// validateは設定値の入力検証を行う
func (cfg *Config) validate() error {
	if cfg.StartPort < 1 || cfg.StartPort > 65535 {
		return fmt.Errorf("開始ポートは1〜65535の範囲で指定してください")
	}
	if cfg.EndPort < 1 || cfg.EndPort > 65535 {
		return fmt.Errorf("終了ポートは1〜65535の範囲で指定してください")
	}
	if cfg.StartPort > cfg.EndPort {
		return fmt.Errorf("開始ポートは終了ポート以下にしてください")
	}
	validProtocols := map[string]bool{"tcp": true, "udp": true, "both": true}
	if !validProtocols[strings.ToLower(cfg.Protocol)] {
		return fmt.Errorf("プロトコルは tcp, udp, both のいずれかで指定してください")
	}
	validScanTypes := map[string]bool{"connect": true, "syn": true, "udp": true}
	if !validScanTypes[strings.ToLower(cfg.ScanType)] {
		return fmt.Errorf("スキャンタイプは connect, syn, udp のいずれかで指定してください")
	}
	if strings.Contains(cfg.TargetIP, "/") {
		if _, _, err := net.ParseCIDR(cfg.TargetIP); err != nil {
			return fmt.Errorf("CIDR表記が不正です")
		}
	} else {
		if len(cfg.TargetIP) == 1 || strings.HasPrefix(cfg.TargetIP, "-") {
			return fmt.Errorf("-iフラグの指定方法が間違っている可能性があります。正しくは -i 192.168.x.x のように指定してください")
		}
		if net.ParseIP(cfg.TargetIP) == nil {
			return fmt.Errorf("IPアドレスの形式が不正です")
		}
	}
	if cfg.ScanSpeed < 1 || cfg.ScanSpeed > 3 {
		return fmt.Errorf("スキャンスピードは1〜3の範囲で指定してください")
	}
	if cfg.TargetIP == "" {
		return fmt.Errorf("Usage: portscanner -i [IPアドレス/CIDR] -s [開始ポート] -e [終了ポート] -t [connect/syn/udp] -p [tcp/udp/both] -S [1-3]")
	}
	return nil
}

// adjustSettingsはスキャン速度に応じてタイムアウトとワーカー数を設定する
func (cfg *Config) adjustSettings() {
	switch cfg.ScanSpeed {
	case 1:
		cfg.Timeout = 2 * time.Second
		cfg.WorkerCount = 10
	case 2:
		cfg.Timeout = 1 * time.Second
		cfg.WorkerCount = 50
	case 3:
		cfg.Timeout = 500 * time.Millisecond
		cfg.WorkerCount = 100
	default:
		fmt.Println("無効なスピード設定です。デフォルト(2)を使用します")
		cfg.Timeout = 1 * time.Second
		cfg.WorkerCount = 50
	}
}

// runScanは設定に基づいてスキャン処理を実行する
func runScan(cfg *Config) {
	if strings.Contains(cfg.TargetIP, "/") {
		hosts := expandCIDR(cfg.TargetIP)
		fmt.Printf("ネットワーク %s 内のホストを探索中...\n", cfg.TargetIP)
		discoveredHosts := discoverHosts(hosts, cfg)
		if len(discoveredHosts) == 0 {
			fmt.Println("アクティブなホストが見つかりませんでした")
			return
		}
		fmt.Printf("%d台のアクティブホストを発見しました\n", len(discoveredHosts))
		for _, host := range discoveredHosts {
			fmt.Printf("ホスト %s のポートスキャンを開始します\n", host)
			scanPorts(host, cfg)
			fmt.Println()
		}
	} else {
		scanPorts(cfg.TargetIP, cfg)
	}
}

///////////////////////////////////////////////////
// Networking & Scanning functions (Refactored)
///////////////////////////////////////////////////

// expandCIDRはCIDR表記からIPアドレスのスライスを返す
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

// incrementIPはIPアドレスをインクリメントする
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// discoverHostsは各ホストにpingし、Linuxの場合はARPスキャンも実施する
func discoverHosts(hosts []string, cfg *Config) []string {
	var discoveredHosts []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := semaphore.NewWeighted(cfg.WorkerCount)
	ctx := context.Background()
	for _, host := range hosts {
		wg.Add(1)
		sem.Acquire(ctx, 1)
		go func(ip string) {
			defer wg.Done()
			defer sem.Release(1)
			alive := pingHost(ip, cfg.Timeout, cfg.Verbose)
			if !alive && isLinux() {
				alive = arpScan(ip, cfg)
			}
			if alive {
				mu.Lock()
				discoveredHosts = append(discoveredHosts, ip)
				mu.Unlock()
				if cfg.Verbose {
					fmt.Printf("Host discovered: %s\n", ip)
				}
			}
		}(host)
	}
	wg.Wait()
	return discoveredHosts
}

// pingHostはICMPパケットでホストの生存を確認する
func pingHost(ip string, timeout time.Duration, verbose bool) bool {
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
	return rm.Type == ipv4.ICMPTypeEchoReply
}

// arpScanはgopacketを用いてARPスキャンを実施する
func arpScan(ip string, cfg *Config) bool {
	iface := selectInterface(cfg)
	switch runtime.GOOS {
	case "linux":
		return arpScanGopacket(iface, ip, cfg.Timeout, cfg.Verbose)
	case "darwin", "windows":
		return arpScanGopacket(iface, ip, cfg.Timeout, cfg.Verbose)
	default:
		fmt.Println("このOSには対応していません")
		return false
	}
}

// arpScanGopacketはARPリクエスト送信・応答受信を行う
func arpScanGopacket(ifaceName, targetIP string, timeout time.Duration, verbose bool) bool {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Printf("インターフェース %s が見つかりません: %v\n", ifaceName, err)
		return false
	}
	localMAC := iface.HardwareAddr
	var localIP net.IP
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			localIP = ipnet.IP
			break
		}
	}
	if localIP == nil {
		fmt.Println("IPv4アドレスが見つかりません")
		return false
	}
	fmt.Printf("選択インターフェース: %s\n", ifaceName)
	fmt.Printf("ローカルIP: %s, MAC: %s\n", localIP, localMAC)

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("pcap.OpenLive失敗: %v\n", err)
		return false
	}
	defer handle.Close()

	target := net.ParseIP(targetIP)
	if target == nil {
		fmt.Println("ターゲットIPのパースに失敗しました")
		return false
	}

	eth := layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(localMAC),
		SourceProtAddress: []byte(localIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(target.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arpLayer); err != nil {
		fmt.Printf("パケット生成失敗: %v\n", err)
		return false
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		fmt.Printf("パケット送信失敗: %v\n", err)
		return false
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeoutCh := time.After(2 * time.Second)
	for {
		select {
		case packet := <-packetSource.Packets():
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply && net.IP(arp.SourceProtAddress).Equal(target) {
					fmt.Printf("%s is at %s\n", target, net.HardwareAddr(arp.SourceHwAddress))
					return true
				}
			}
		case <-timeoutCh:
			fmt.Println("ARP応答がありませんでした")
			return false
		}
	}
}

// scanPortsは対象ホストのポートスキャンを実行する
func scanPorts(ip string, cfg *Config) {
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

// scanTCPPortsはTCPポートスキャンを実施する
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

// scanTCPConnectはTCPコネクトスキャンを実施する
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

// scanTCPSynはSYNスキャンを実施する。root権限がない場合はConnect Scanにフォールバックする
func scanTCPSyn(ip string, port int, cfg *Config) {
	if os.Getuid() != 0 {
		if port == cfg.StartPort {
			fmt.Println("SYN scan requires root privileges. Connect scan will be used instead.")
		}
		scanTCPConnect(ip, port, cfg)
		return
	}
	// 現状はConnect Scanと同等の実装（実際のSYNスキャン実装は別途検討）
	scanTCPConnect(ip, port, cfg)
}

// scanUDPPortsはUDPポートスキャンを実施する
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

// scanUDPはUDPスキャンを1ポートごとに実施する
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

// createUDPProbeはポートに応じたUDPプローブペイロードを返す
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

// getServiceNameはプロトコルとポートに応じたサービス名を返す
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

// isLinuxは環境変数によりLinuxかどうかを判定する
func isLinux() bool {
	return os.Getenv("OS") != "Windows_NT"
}

// selectInterfaceは利用可能なインターフェースを自動選択または対話的に選択する
func selectInterface(cfg *Config) string {
	if cfg.IfaceName != "" {
		return cfg.IfaceName
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("インターフェース列挙に失敗: %v\n", err)
		os.Exit(1)
	}
	var candidates []pcap.Interface
	for _, dev := range devices {
		if strings.Contains(dev.Name, "lo") {
			continue
		}
		iface, err := net.InterfaceByName(dev.Name)
		if err != nil || len(iface.HardwareAddr) == 0 {
			continue
		}
		hasIPv4 := false
		for _, addr := range dev.Addresses {
			if addr.IP.To4() != nil {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		candidates = append(candidates, dev)
	}
	if len(candidates) == 0 {
		fmt.Println("利用可能なインターフェースが見つかりませんでした")
		os.Exit(1)
	}
	if len(candidates) == 1 {
		return candidates[0].Name
	}
	fmt.Println("利用可能なインターフェース:")
	for i, dev := range candidates {
		fmt.Printf("[%d] %s (%s)\n", i, dev.Name, dev.Description)
	}
	fmt.Print("番号を選択してください: ")
	reader := bufio.NewReader(os.Stdin)
	var idx int
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		_, err := fmt.Sscanf(input, "%d", &idx)
		if err == nil && idx >= 0 && idx < len(candidates) {
			break
		}
		fmt.Print("正しい番号を入力してください: ")
	}
	return candidates[idx].Name
}
