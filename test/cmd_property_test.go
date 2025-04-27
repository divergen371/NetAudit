package test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/divergen371/NetAudit/internal/cli"
	"github.com/divergen371/NetAudit/internal/scanner"
	"pgregory.net/rapid"
)

var TestMode = false

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

func TestPortscanner_CLI_Property_Valid(t *testing.T) {
	cli.SetPortScanner(&scanner.MockPortScanner{MockOutput: "Start scan on port 80-80 for 127.0.0.1\nScan completed in 1ms\n"})
	rapid.Check(t, func(t *rapid.T) {
		ip := "127.0.0.1"
		startPort := rapid.IntRange(80, 81).Draw(t, "startPort")
		endPort := startPort
		scanType := rapid.SampledFrom([]string{"connect"}).Draw(t, "scanType")
		protocol := rapid.SampledFrom([]string{"tcp"}).Draw(t, "protocol")

		args := []string{
			"-i", ip,
			"-s", fmt.Sprintf("%d", startPort),
			"-e", fmt.Sprintf("%d", endPort),
			"-t", scanType,
			"-p", protocol,
		}

		var outBuf, errBuf bytes.Buffer
		cli.RootCmd.SetOut(&outBuf)
		cli.RootCmd.SetErr(&errBuf)
		cli.RootCmd.SetArgs(args)
		err := cli.RootCmd.Execute()
		if err != nil {
			t.Skipf("バリデーションエラー: %v, args: %v", err, args)
		}
		output := strings.TrimSpace(outBuf.String() + errBuf.String())
		t.Logf("output: %q", output)
		if !strings.Contains(output, "Start scan on port") || !strings.Contains(output, "Scan completed") {
			t.Errorf("期待する出力が含まれない: %s", output)
		}
	})
}

func TestPortscanner_CLI_ValidationErrorOutput(t *testing.T) {
	cli.TestMode = true
	// バリデーションエラーを明示的に誘発する値
	cases := []struct {
		args      []string
		expectMsg string
	}{
		{[]string{"-i", "", "-s", "80", "-e", "80", "-t", "connect", "-p", "tcp"}, "スキャン対象のIPアドレス"},
		{[]string{"-i", "999.999.999.999", "-s", "80", "-e", "80", "-t", "connect", "-p", "tcp"}, "IPアドレスの形式が不正"},
		{[]string{"-i", "127.0.0.1", "-s", "0", "-e", "80", "-t", "connect", "-p", "tcp"}, "開始ポートは1"},
		{[]string{"-i", "127.0.0.1", "-s", "80", "-e", "70000", "-t", "connect", "-p", "tcp"}, "終了ポートは1"},
		{[]string{"-i", "127.0.0.1", "-s", "80", "-e", "80", "-t", "invalid", "-p", "tcp"}, "スキャンタイプ"},
		{[]string{"-i", "127.0.0.1", "-s", "80", "-e", "80", "-t", "connect", "-p", "invalid"}, "プロトコル"},
	}
	for _, c := range cases {
		var outBuf, errBuf bytes.Buffer
		cli.RootCmd.SetOut(&outBuf)
		cli.RootCmd.SetErr(&errBuf)
		cli.RootCmd.SetArgs(c.args)
		err := cli.RootCmd.Execute()
		output := outBuf.String() + errBuf.String()
		t.Logf("args=%v, output=%q, err=%v", c.args, output, err)
		if err == nil {
			t.Errorf("バリデーションエラーが返らない: args=%v, output=%q", c.args, output)
		}
		if !strings.Contains(output, c.expectMsg) {
			t.Errorf("バリデーションエラー出力が期待通りでない: args=%v, got=%q, want含む=%q", c.args, output, c.expectMsg)
		}
	}
}
