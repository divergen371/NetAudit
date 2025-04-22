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
	ifaceName   string
)

var rootCmd = &cobra.Command{
	Use:   "portscanner",
	Short: "シンプルなポートスキャナ",
	Long:  `IPアドレスやCIDR範囲を指定してポートスキャンを行うツールです。`,
	Run: func(cmd *cobra.Command, args []string) {
		// --- バリデーション強化 ---
		if startPort < 1 || startPort > 65535 {
			fmt.Println("開始ポートは1〜65535の範囲で指定してください")
			os.Exit(1)
		}
		if endPort < 1 || endPort > 65535 {
			fmt.Println("終了ポートは1〜65535の範囲で指定してください")
			os.Exit(1)
		}
		if startPort > endPort {
			fmt.Println("開始ポートは終了ポート以下にしてください")
			os.Exit(1)
		}
		validProtocols := map[string]bool{"tcp": true, "udp": true, "both": true}
		if !validProtocols[strings.ToLower(protocol)] {
			fmt.Println("プロトコルは tcp, udp, both のいずれかで指定してください")
			os.Exit(1)
		}
		validScanTypes := map[string]bool{"connect": true, "syn": true, "udp": true}
		if !validScanTypes[strings.ToLower(scanType)] {
			fmt.Println("スキャンタイプは connect, syn, udp のいずれかで指定してください")
			os.Exit(1)
		}
		if strings.Contains(targetIP, "/") {
			if _, _, err := net.ParseCIDR(targetIP); err != nil {
				fmt.Println("CIDR表記が不正です")
				os.Exit(1)
			}
		} else {
			if len(targetIP) == 1 || strings.HasPrefix(targetIP, "-") {
				fmt.Println("-iフラグの指定方法が間違っている可能性があります。正しくは -i 192.168.x.x のように指定してください")
				os.Exit(1)
			}
			if net.ParseIP(targetIP) == nil {
				fmt.Println("IPアドレスの形式が不正です")
				os.Exit(1)
			}
		}
		if scanSpeed < 1 || scanSpeed > 3 {
			fmt.Println("スキャンスピードは1〜3の範囲で指定してください")
			os.Exit(1)
		}
		// 各フラグの指定方法ミスを検出
		if strings.HasPrefix(cmd.Flag("i").Value.String(), "-") {
			fmt.Println("-iフラグの指定方法が間違っている可能性があります。正しくは -i 192.168.x.x のように指定してください")
			os.Exit(1)
		}
		if strings.HasPrefix(cmd.Flag("s").Value.String(), "-") {
			fmt.Println("-sフラグの指定方法が間違っている可能性があります。正しくは -s 1 のように指定してください")
			os.Exit(1)
		}
		if strings.HasPrefix(cmd.Flag("e").Value.String(), "-") {
			fmt.Println("-eフラグの指定方法が間違っている可能性があります。正しくは -e 1000 のように指定してください")
			os.Exit(1)
		}
		if strings.HasPrefix(cmd.Flag("t").Value.String(), "-") {
			fmt.Println("-tフラグの指定方法が間違っている可能性があります。正しくは -t connect のように指定してください")
			os.Exit(1)
		}
		if strings.HasPrefix(cmd.Flag("p").Value.String(), "-") {
			fmt.Println("-pフラグの指定方法が間違っている可能性があります。正しくは -p tcp のように指定してください")
			os.Exit(1)
		}
		if strings.HasPrefix(cmd.Flag("S").Value.String(), "-") {
			fmt.Println("-Sフラグの指定方法が間違っている可能性があります。正しくは -S 2 のように指定してください")
			os.Exit(1)
		}
		// --- ここまでバリデーション ---

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
			fmt.Println("Usage: portscanner -i [IPアドレス/CIDR] -s [開始ポート] -e [終了ポート] -t [connect/syn/udp] -p [tcp/udp/both] -S [1-3]")
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
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&targetIP, "i", "i", "", "スキャン対象のIPアドレスまたはCIDR範囲（例: 192.168.1.1 または 192.168.1.0/24）【必須】")
	rootCmd.PersistentFlags().IntVarP(&startPort, "s", "s", 1, "スキャン開始ポート (デフォルト: 1)")
	rootCmd.PersistentFlags().IntVarP(&endPort, "e", "e", 1000, "スキャン終了ポート (デフォルト: 1000)")
	rootCmd.PersistentFlags().StringVarP(&scanType, "t", "t", "connect", "スキャンタイプ (connect, syn, udp) (デフォルト: connect)")
	rootCmd.PersistentFlags().StringVarP(&protocol, "p", "p", "tcp", "プロトコル (tcp, udp, both) (デフォルト: tcp)")
	rootCmd.PersistentFlags().IntVarP(&scanSpeed, "S", "S", 2, "スキャンスピード (1=遅い, 2=普通, 3=速い) (デフォルト: 2)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "v", "v", false, "詳細出力を有効化")
	rootCmd.PersistentFlags().StringVarP(&ifaceName, "I", "I", "", "利用するネットワークインターフェース名（例: eth0, en0 など）")

	rootCmd.MarkPersistentFlagRequired("i")
}

func main() {
	// 既存のflagパース処理は一旦コメントアウト
	// flag.StringVar(&targetIP, "ip", "", "スキャン対象のIPアドレスまたはCIDR範囲（例: 192.168.1.1 または 192.168.1.0/24）")
	// flag.IntVar(&startPort, "start", 1, "スキャン開始ポート")
	// flag.IntVar(&endPort, "end", 1000, "スキャン終了ポート")
	// flag.StringVar(&scanType, "type", "connect", "スキャンタイプ (connect, syn, udp)")
	// flag.StringVar(&protocol, "proto", "tcp", "プロトコル (tcp, udp, both)")
	// flag.IntVar(&scanSpeed, "speed", 2, "スキャンスピード (1=遅い, 2=普通, 3=速い)")
	// flag.BoolVar(&verbose, "v", false, "詳細出力")
	// flag.Parse()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
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
	iface := selectInterface()
	switch runtime.GOOS {
	case "linux":
		// gopacketでARPリクエスト送信・応答受信
		return arpScanGopacket(iface, ip)
	case "darwin", "windows":
		return arpScanGopacket(iface, ip)
	default:
		fmt.Println("このOSには対応していません")
		return false
	}
}

// gopacketを使ったARPリクエスト送信・応答受信の雛形
func arpScanGopacket(ifaceName, targetIP string) bool {
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

func selectInterface() string {
	if ifaceName != "" {
		return ifaceName
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("インターフェース列挙に失敗: %v\n", err)
		os.Exit(1)
	}
	candidates := []pcap.Interface{}
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
