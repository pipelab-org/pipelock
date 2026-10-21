// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMCPEmitConfig(t *testing.T, emitSection string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	data := `mode: balanced
mcp_input_scanning:
  enabled: true
  action: block
mcp_tool_scanning:
  enabled: false
mcp_tool_policy:
  enabled: false
logging:
  format: json
  output: stdout
  include_blocked: true
` + emitSection
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mcpEmitProxyArgs(configPath string) []string {
	return []string{
		"proxy",
		"--config", configPath,
		"--env", "PIPELOCK_TEST_MCP_HELPER=1",
		"--",
		os.Args[0],
		"-test.run=TestMCPRuntimeHelperProcess$",
	}
}

// TestMCPProxyRefusesStartWhenEmitSinkCannotBeBuilt proves the wrapper fails
// closed: a configured audit destination that cannot be created stops startup
// before the wrapped server is launched.
func TestMCPProxyRefusesStartWhenEmitSinkCannotBeBuilt(t *testing.T) {
	// A valid tcp syslog address with nothing listening: the sink dials at
	// construction, so building it fails with connection refused.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	configPath := writeMCPEmitConfig(t, fmt.Sprintf(`emit:
  syslog:
    address: "tcp://%s"
`, closedAddr))
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"runtime-test","version":"0"}}}` + "\n"

	stdout, stderr, err := runMCPProxyCommandWithInput(t, mcpEmitProxyArgs(configPath), input)
	if err == nil {
		t.Fatalf("expected startup to fail with an unusable syslog sink\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(err.Error(), "creating emit sinks") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(stdout, "test-mcp-helper") {
		t.Fatalf("wrapped server answered initialize; startup did not abort before launch:\n%s", stdout)
	}
}
