package test

import (
	"strings"
	"testing"

	"github.com/divergen371/NetAudit/internal/cli"
	"pgregory.net/rapid"
)

func TestPortscanner_CLI_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// ランダムなIPアドレス/CIDR
		ip := rapid.StringMatching(`^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$`).Draw(t, "ip")
		// スキャンタイプ
		scanType := rapid.SampledFrom([]string{"connect", "syn", "udp"}).Draw(t, "scanType")
		// プロトコル
		protocol := rapid.SampledFrom([]string{"tcp", "udp", "both"}).Draw(t, "protocol")

		args := []string{
			"-i", ip,
			"-s", rapid.String().Draw(t, "s"),
			"-e", rapid.String().Draw(t, "e"),
			"-t", scanType,
			"-p", protocol,
		}

		cli.RootCmd.SetArgs(args)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CLI panicked with args: %v, panic: %v", args, r)
			}
		}()
		err := cli.RootCmd.Execute()
		if err != nil && !strings.Contains(err.Error(), "Usage:") {
			t.Logf("CLI error (許容): %v, args: %v", err, args)
		}
	})
}
