package network

import (
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"
)

// バナー判定ルール
type bannerRule struct {
	Protocol   string
	Keyword    string
	ReturnTmpl string // %sにバナー内容が入る
}

var bannerRules = []bannerRule{
	{"ftp", "FTP", "ftp server: %s"},
	{"ssh", "OpenSSH_for_Windows", "windows (OpenSSH): %s"},
	{"ssh", "Win32-OpenSSH", "windows (OpenSSH): %s"},
	{"ssh", "SSH", "linux/unix (OpenSSH/SSH)"},
	{"telnet", "login", "telnet server: %s"},
	{"telnet", "Telnet", "telnet server: %s"},
	{"smtp", "SMTP", "smtp server: %s"},
	{"smtp", "ESMTP", "smtp server: %s"},
	{"http", "HTTP/", "http server: %s"},
	{"http", "Server:", "http server: %s"},
	{"pop3", "+OK", "pop3 server: %s"},
	{"imap4", "IMAP", "imap4 server: %s"},
	{"imap4", "OK", "imap4 server: %s"},
	{"memcached", "VERSION", "memcached: %s"},
	{"ssl", "SSL", "ssl/tls service: %s"},
	{"smbv1", "smb", "smb service: %s"},
	{"smbv2", "smb", "smb service: %s"},
	{"rdp", "RDP", "rdp service: %s"},
	{"vnc", "RFB", "vnc service: %s"},
	{"vnc", "VNC", "vnc service: %s"},
}

// DetectLocalOS はこのプログラムが動作しているOS名を返す
func DetectLocalOS() string {
	return runtime.GOOS
}

// DetectRemoteOS は指定IPのリモートOSを推測する（バナーグラビング優先、失敗時はTTL）
func DetectRemoteOS(ip string) string {
	bannerResult := bannerGrab(ip)
	if bannerResult != "" {
		return bannerResult
	}
	return detectOSByTTL(ip)
}

// bannerGrabは代表的なポートでバナーグラビングを行い、推測結果またはバナー文字列を返す
func bannerGrab(ip string) string {
	ports := map[string]int{
		"ftp":       21,
		"ssh":       22,
		"telnet":    23,
		"smtp":      25,
		"http":      80,
		"pop3":      110,
		"imap4":     143,
		"ssl":       443,
		"smbv1":     445,
		"smbv2":     445,
		"rdp":       3389,
		"vnc":       5900,
		"memcached": 11211,
	}
	for proto, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		var banner string
		var err error
		if proto == "ssl" {
			banner, err = grabSSLBanner(addr)
		} else {
			banner, err = grabTCPBanner(addr, proto)
		}
		if err == nil && banner != "" {
			for _, rule := range bannerRules {
				if rule.Protocol == proto && strings.Contains(strings.ToLower(banner), strings.ToLower(rule.Keyword)) {
					return fmt.Sprintf(rule.ReturnTmpl, strings.TrimSpace(banner))
				}
			}
			// 一般的なバナーも返す
			return fmt.Sprintf("%s banner: %s", proto, strings.TrimSpace(banner))
		}
	}
	return ""
}

// grabTCPBannerはTCPで接続し、必要に応じて簡易リクエストを送信してバナーを取得する
func grabTCPBanner(addr, proto string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// プロトコルごとに簡易リクエスト
	switch proto {
	case "http":
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	case "memcached":
		conn.Write([]byte("version\r\n"))
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}

// grabSSLBannerはSSL/TLSで接続し、証明書情報などを取得する
func grabSSLBanner(addr string) (string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		return "SSL Cert CN: " + cert.Subject.CommonName, nil
	}
	return "SSL handshake success", nil
}

// detectOSByTTLはICMPのTTL値からOSを推測する
func detectOSByTTL(ip string) string {
	conn, err := net.DialTimeout("ip4:icmp", ip, 2*time.Second)
	if err != nil {
		return "unknown"
	}
	defer conn.Close()

	// ICMP Echo Requestパケットを作成
	msg := []byte{
		8, 0, 0, 0, 0, 13, 0, 37, // type, code, checksum, id, seq
	}
	_, err = conn.Write(msg)
	if err != nil {
		return "unknown"
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	_, err = conn.Read(buf)
	if err != nil {
		return "unknown"
	}

	// TTL値はOSによって異なる。ICMPヘッダの直前にIPヘッダがある。
	// IPヘッダの9バイト目がTTL
	if len(buf) < 9 {
		return "unknown"
	}
	ttl := int(buf[8])

	switch {
	case ttl >= 120 && ttl <= 130:
		return "windows"
	case ttl >= 60 && ttl <= 70:
		return "linux/unix"
	case ttl >= 240:
		return "network device"
	default:
		return "unknown"
	}
}
