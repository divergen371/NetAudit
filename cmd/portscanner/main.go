package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/divergen371/NetAudit/internal/config"
	"github.com/divergen371/NetAudit/internal/network"
	"github.com/divergen371/NetAudit/internal/scanner"

	"github.com/spf13/cobra"
)

var cfg config.Config

var rootCmd = &cobra.Command{
	Use:   "portscanner",
	Short: "シンプルなポートスキャナ",
	Long:  "IPアドレスやCIDR範囲を指定してポートスキャンを行うツールです.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.ValidateConfig(&cfg); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		adjustSettings(&cfg)
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

// adjustSettingsはスキャン速度に応じてタイムアウトとワーカー数を設定する
func adjustSettings(cfg *config.Config) {
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
func runScan(cfg *config.Config) {
	if strings.Contains(cfg.TargetIP, "/") {
		hosts := network.ExpandCIDR(cfg.TargetIP)
		fmt.Printf("ネットワーク %s 内のホストを探索中...\n", cfg.TargetIP)
		discoveredHosts := scanner.DiscoverHosts(hosts, cfg)
		if len(discoveredHosts) == 0 {
			fmt.Println("アクティブなホストが見つかりませんでした")
			return
		}
		fmt.Printf("%d台のアクティブホストを発見しました\n", len(discoveredHosts))
		for _, host := range discoveredHosts {
			fmt.Printf("ホスト %s のポートスキャンを開始します\n", host)
			scannerCfg := &scanner.Config{
				StartPort:   cfg.StartPort,
				EndPort:     cfg.EndPort,
				ScanType:    cfg.ScanType,
				Protocol:    cfg.Protocol,
				Timeout:     cfg.Timeout,
				WorkerCount: cfg.WorkerCount,
				Verbose:     cfg.Verbose,
			}
			scanner.ScanPorts(host, scannerCfg)
			fmt.Println()
		}
	} else {
		scannerCfg := &scanner.Config{
			StartPort:   cfg.StartPort,
			EndPort:     cfg.EndPort,
			ScanType:    cfg.ScanType,
			Protocol:    cfg.Protocol,
			Timeout:     cfg.Timeout,
			WorkerCount: cfg.WorkerCount,
			Verbose:     cfg.Verbose,
		}
		scanner.ScanPorts(cfg.TargetIP, scannerCfg)
	}
}
