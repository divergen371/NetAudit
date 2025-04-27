package scanner

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ARPConfig struct {
	IfaceName string
	Timeout   time.Duration
	Verbose   bool
}

func ARPScan(ip string, cfg *ARPConfig) bool {
	iface := cfg.IfaceName
	if iface == "" {
		iface = selectInterfaceByPcap()
	}
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return arpScanGopacket(iface, ip, cfg.Timeout, cfg.Verbose)
	default:
		fmt.Println("このOSには対応していません")
		return false
	}
}

func handleARPVerboseLog(phase string, data ...interface{}) {
	if len(data) == 0 {
		fmt.Printf("[ARP] %s\n", phase)
		return
	}
	switch phase {
	case "インターフェース取得":
		fmt.Printf("[ARP] インターフェース取得: %s\n", data[0])
	case "ローカルIP":
		fmt.Printf("[ARP] ローカルIP: %s, MAC: %s\n", data[0], data[1])
	case "パケット生成":
		fmt.Printf("[ARP] パケット生成中...\n")
	case "パケット送信":
		fmt.Printf("[ARP] パケット送信中...\n")
	case "応答待ち":
		fmt.Printf("[ARP] 応答待ち...\n")
	case "他ホスト応答":
		fmt.Printf("[ARP] 他ホストからのARP応答: %s is at %s\n", data[0], data[1])
	}
}

func getInterfaceInfo(ifaceName string, verbose bool) (net.HardwareAddr, net.IP, error) {
	if verbose {
		handleARPVerboseLog("インターフェース取得", ifaceName)
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("インターフェース %s が見つかりません: %v", ifaceName, err)
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
		return nil, nil, fmt.Errorf("IPv4アドレスが見つかりません")
	}
	if verbose {
		handleARPVerboseLog("ローカルIP", localIP, localMAC)
	}
	return localMAC, localIP, nil
}

func createARPPacket(localMAC net.HardwareAddr, localIP net.IP, targetIP net.IP, verbose bool) ([]byte, error) {
	if verbose {
		handleARPVerboseLog("パケット生成")
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
		DstProtAddress:    []byte(targetIP.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arpLayer); err != nil {
		return nil, fmt.Errorf("パケット生成失敗: %v", err)
	}
	return buf.Bytes(), nil
}

func sendARPPacket(handle *pcap.Handle, packet []byte, verbose bool) error {
	if verbose {
		handleARPVerboseLog("パケット送信")
	}
	if err := handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("パケット送信失敗: %v", err)
	}
	return nil
}

func waitARPReply(handle *pcap.Handle, target net.IP, timeout time.Duration, verbose bool) (bool, error) {
	if verbose {
		handleARPVerboseLog("応答待ち")
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeoutCh := time.After(timeout)
	for {
		select {
		case packet := <-packetSource.Packets():
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply && net.IP(arp.SourceProtAddress).Equal(target) {
					fmt.Printf("%s is at %s\n", target, net.HardwareAddr(arp.SourceHwAddress))
					return true, nil
				} else if verbose {
					handleARPVerboseLog("他ホスト応答", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
				}
			}
		case <-timeoutCh:
			fmt.Println("ARP応答がありませんでした")
			return false, nil
		}
	}
}

func arpScanGopacket(ifaceName, targetIP string, timeout time.Duration, verbose bool) bool {
	localMAC, localIP, err := getInterfaceInfo(ifaceName, verbose)
	if err != nil {
		fmt.Println(err)
		return false
	}
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
	packet, err := createARPPacket(localMAC, localIP, target, verbose)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if err := sendARPPacket(handle, packet, verbose); err != nil {
		fmt.Println(err)
		return false
	}
	found, _ := waitARPReply(handle, target, timeout, verbose)
	return found
}

// selectInterfaceByPcapは対話的にインターフェースを選択する（main.goのselectInterfaceの簡易版）
func selectInterfaceByPcap() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("インターフェース列挙に失敗: %v\n", err)
		os.Exit(1)
	}
	var candidates []pcap.Interface
	for _, dev := range devices {
		if len(dev.Addresses) == 0 || len(dev.Name) == 0 {
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
	var idx int
	fmt.Print("番号を選択してください: ")
	fmt.Scanf("%d", &idx)
	return candidates[idx].Name
}
