package config

import (
	"fmt"
	"net"
	"strings"
)

func ValidateConfig(cfg *Config) error {
	if err := validatePortRange(cfg); err != nil {
		return err
	}
	if err := validateProtocol(cfg); err != nil {
		return err
	}
	if err := validateScanType(cfg); err != nil {
		return err
	}
	if err := validateTargetIP(cfg); err != nil {
		return err
	}
	if err := validateScanSpeed(cfg); err != nil {
		return err
	}
	if err := validateRequired(cfg); err != nil {
		return err
	}
	return nil
}

func validatePortRange(cfg *Config) error {
	if cfg.StartPort < 1 || cfg.StartPort > 65535 {
		return fmt.Errorf("開始ポートは1〜65535の範囲で指定してください")
	}
	if cfg.EndPort < 1 || cfg.EndPort > 65535 {
		return fmt.Errorf("終了ポートは1〜65535の範囲で指定してください")
	}
	if cfg.StartPort > cfg.EndPort {
		return fmt.Errorf("開始ポートは終了ポート以下にしてください")
	}
	return nil
}

func validateProtocol(cfg *Config) error {
	validProtocols := map[string]bool{"tcp": true, "udp": true, "both": true}
	if !validProtocols[strings.ToLower(cfg.Protocol)] {
		return fmt.Errorf("プロトコルは tcp, udp, both のいずれかで指定してください")
	}
	return nil
}

func validateScanType(cfg *Config) error {
	validScanTypes := map[string]bool{"connect": true, "syn": true, "udp": true}
	if !validScanTypes[strings.ToLower(cfg.ScanType)] {
		return fmt.Errorf("スキャンタイプは connect, syn, udp のいずれかで指定してください")
	}
	return nil
}

func validateTargetIP(cfg *Config) error {
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
	return nil
}

func validateScanSpeed(cfg *Config) error {
	if cfg.ScanSpeed < 1 || cfg.ScanSpeed > 3 {
		return fmt.Errorf("スキャンスピードは1〜3の範囲で指定してください")
	}
	return nil
}

func validateRequired(cfg *Config) error {
	if cfg.TargetIP == "" {
		return fmt.Errorf("Usage: portscanner -i [IPアドレス/CIDR] -s [開始ポート] -e [終了ポート] -t [connect/syn/udp] -p [tcp/udp/both] -S [1-3]")
	}
	return nil
}
