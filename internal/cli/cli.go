package cli

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

var Cfg config.Config

// PortScannerインターフェースのグローバル変数
var portScanner scanner.PortScanner = &scanner.RealPortScanner{}

// テスト用に差し替え可能にするためのSetter
func SetPortScanner(s scanner.PortScanner) {
	portScanner = s
}

// テスト用: os.Exitを抑制するフラグ
var TestMode = false

var RootCmd = &cobra.Command{
	Use:   "portscanner",
	Short: "シンプルなポートスキャナ",
	Long:  "IPアドレスやCIDR範囲を指定してポートスキャンを行うツールです.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.ValidateConfig(&Cfg); err != nil {
			fmt.Fprintln(cmd.OutOrStderr(), err)
			if !TestMode {
				os.Exit(1)
			}
			return err
		}
		adjustSettings(&Cfg)
		runScan(cmd, &Cfg)
		return nil
	},
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&Cfg.TargetIP, "i", "i", "", "スキャン対象のIPアドレスまたはCIDR範囲（例: 192.168.1.1 または 192.168.1.0/24）【必須】")
	RootCmd.PersistentFlags().IntVarP(&Cfg.StartPort, "s", "s", 1, "スキャン開始ポート (デフォルト: 1)")
	RootCmd.PersistentFlags().IntVarP(&Cfg.EndPort, "e", "e", 1000, "スキャン終了ポート (デフォルト: 1000)")
	RootCmd.PersistentFlags().StringVarP(&Cfg.ScanType, "t", "t", "connect", "スキャンタイプ (connect, syn, udp) (デフォルト: connect)")
	RootCmd.PersistentFlags().StringVarP(&Cfg.Protocol, "p", "p", "tcp", "プロトコル (tcp, udp, both) (デフォルト: tcp)")
	RootCmd.PersistentFlags().IntVarP(&Cfg.ScanSpeed, "S", "S", 2, "スキャンスピード (1=遅い, 2=普通, 3=速い) (デフォルト: 2)")
	RootCmd.PersistentFlags().BoolVarP(&Cfg.Verbose, "v", "v", false, "詳細出力を有効化")
	RootCmd.PersistentFlags().StringVarP(&Cfg.IfaceName, "I", "I", "", "利用するネットワークインターフェース名（例: eth0, en0 など）")

	RootCmd.MarkPersistentFlagRequired("i")
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

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

func runScan(cmd *cobra.Command, cfg *config.Config) {
	if strings.Contains(cfg.TargetIP, "/") {
		hosts := network.ExpandCIDR(cfg.TargetIP)
		fmt.Fprintf(cmd.OutOrStdout(), "ネットワーク %s 内のホストを探索中...\n", cfg.TargetIP)
		discoveredHosts := scanner.DiscoverHosts(hosts, cfg)
		if len(discoveredHosts) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "アクティブなホストが見つかりませんでした")
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%d台のアクティブホストを発見しました\n", len(discoveredHosts))
		for _, host := range discoveredHosts {
			fmt.Fprintf(cmd.OutOrStdout(), "ホスト %s のポートスキャンを開始します\n", host)
			scannerCfg := &scanner.Config{
				StartPort:   cfg.StartPort,
				EndPort:     cfg.EndPort,
				ScanType:    cfg.ScanType,
				Protocol:    cfg.Protocol,
				Timeout:     cfg.Timeout,
				WorkerCount: cfg.WorkerCount,
				Verbose:     cfg.Verbose,
			}
			portScanner.ScanPorts(cmd.OutOrStdout(), host, scannerCfg)
			fmt.Fprintln(cmd.OutOrStdout())
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
		portScanner.ScanPorts(cmd.OutOrStdout(), cfg.TargetIP, scannerCfg)
	}
}
