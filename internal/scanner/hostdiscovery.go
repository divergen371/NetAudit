package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/divergen371/NetAudit/internal/config"
	"golang.org/x/sync/semaphore"
)

// DiscoverHostsは各ホストにICMP/ARPで生存確認し、アクティブなホスト一覧を返す
func DiscoverHosts(hosts []string, cfg *config.Config) []string {
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
			alive := isHostAliveICMP(ip, cfg)
			if !alive && isLinux() {
				alive = isHostAliveARP(ip, cfg)
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

func isHostAliveICMP(ip string, cfg *config.Config) bool {
	icmpCfg := &ICMPConfig{
		Timeout: cfg.Timeout,
		Verbose: cfg.Verbose,
	}
	return PingHost(ip, icmpCfg)
}

func isHostAliveARP(ip string, cfg *config.Config) bool {
	arpCfg := &ARPConfig{
		IfaceName: cfg.IfaceName,
		Timeout:   cfg.Timeout,
		Verbose:   cfg.Verbose,
	}
	return ARPScan(ip, arpCfg)
}

func isLinux() bool {
	return true // 本来はOS判定。main.goのisLinuxと合わせて調整可
}
