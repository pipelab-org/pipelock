// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !mcp_hardening_test

package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/testport"
)

// TestMCPSandboxMetricsDialUsesBoundAddress drives `mcp proxy --sandbox` end
// to end. MCP mode binds the metrics listener before it builds the bridge
// proxy, so a hostname that resolves differently afterwards leaves the
// bridge's configured target naming another address. The sandboxed server
// must still be refused the address the listener actually bound.
func TestMCPSandboxMetricsDialUsesBoundAddress(t *testing.T) {
	// Check prerequisites before re-executing: a skip inside the child exits
	// zero, which the parent would otherwise report as a pass.
	if sandbox.Detect().LandlockABI == 0 {
		t.Skip("kernel does not support Landlock")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is required for real sandbox traffic")
	}
	// The MCP command marks its process non-dumpable, so run this in a fresh
	// process as a separate CLI invocation would.
	const helperEnv = "PIPELOCK_TEST_MCP_SANDBOX_METRICS"
	if os.Getenv(helperEnv) != "1" {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPSandboxMetricsDialUsesBoundAddress$", "-test.timeout=50s") // #nosec G204 G702 -- test re-execs its own binary with fixed arguments
		child.Env = append(os.Environ(), helperEnv+"=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("MCP sandbox invocation: %v\n%s", err, output)
		}
		return
	}
	_, port, err := net.SplitHostPort(testport.ListenAddrs(t, 1)[0])
	if err != nil {
		t.Fatal(err)
	}
	boundAddr := net.JoinHostPort("127.0.0.2", port)
	// Answer the bound address until that listener is live, and a different
	// local address afterwards, so the bridge's own lookup sees the drift.
	useMetricsTestDNS(t, func() [4]byte {
		conn, dialErr := (&net.Dialer{Timeout: time.Second}).Dial("tcp", boundAddr)
		if dialErr != nil {
			return [4]byte{127, 0, 0, 2}
		}
		_ = conn.Close()
		return [4]byte{127, 0, 0, 1}
	})
	workspace := t.TempDir()
	path := writeServerTestConfig(t, fmt.Sprintf("ssrf:\n  ip_allowlist: ['127.0.0.0/8']\nmetrics_listen: %q\n", net.JoinHostPort("metrics.vendor.example", port)))
	script := `for route in metrics stats; do
 curl --max-time 5 --noproxy '*' -s -o /dev/null -w '%{http_code}\n' "$HTTP_PROXY/fetch?url=http://$1/$route" >> metrics-dial
done
`
	args := []string{
		"proxy", "--config", path, "--sandbox", "--workspace", workspace,
		"--sandbox-best-effort", "--sandbox-best-effort-reason", "metrics dial test",
		"--sandbox-best-effort-expiry", "1m",
		"--", "/bin/sh", "-c", script, "metrics-test", boundAddr,
	}
	// The bridge and the sandboxed child both write diagnostics concurrently,
	// so capture them through a synchronized buffer.
	var output syncBuffer
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	cmd := McpCmd()
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs(args)
	runErr := cmd.ExecuteContext(ctx)
	stderr := output.String()
	if !strings.Contains(stderr, "metrics listening on "+boundAddr) {
		t.Fatalf("metrics listener did not bind %s: %v\nstderr:\n%s", boundAddr, runErr, stderr)
	}
	dialStatus, readErr := os.ReadFile(filepath.Clean(filepath.Join(workspace, "metrics-dial")))
	if readErr != nil || string(dialStatus) != "403\n403\n" {
		t.Fatalf("sandboxed metrics dial = %q, %v; run error: %v\nstderr:\n%s", dialStatus, readErr, runErr, stderr)
	}
}
