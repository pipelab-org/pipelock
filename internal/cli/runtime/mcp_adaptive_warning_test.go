// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPProxyWarningsKeepProtocolStdoutAndDiscoveryUsable(t *testing.T) {
	upstream := e2eToolsListUpstream(t)
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	text := `version: 1
mode: balanced
logging:
  format: json
  output: stdout
mcp_input_scanning:
  enabled: true
  action: warn
mcp_tool_scanning:
  enabled: false
session_profiling:
  enabled: true
adaptive_enforcement:
  enabled: true
  escalation_threshold: 5
  decay_per_clean_request: 0.5
dlp:
  patterns:
    - name: Coordination marker
      regex: coordination-marker
      severity: low
`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	p := startE2EProxy(t, []string{"proxy", "--config", path, "--upstream", upstream.URL})
	for i := range 25 {
		msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"coordinate","arguments":{"text":"coordination-marker"}}}`, i+2)
		got, ok := p.tryCall(msg)
		if !ok || !json.Valid([]byte(got)) || !strings.Contains(got, `"jsonrpc":"2.0"`) || strings.Contains(got, `"error"`) {
			t.Fatalf("warning call %d: %q; stderr: %s", i, got, p.stderr.String())
		}
	}
	if got := p.call(); !strings.Contains(got, `"result"`) {
		t.Fatalf("discovery refused after warnings: %s", got)
	}
	stderr, err := p.finish()
	if err != nil {
		t.Fatalf("proxy exit: %v; stderr: %s", err, stderr)
	}
	if !strings.Contains(stderr, "Coordination marker") {
		t.Fatalf("warning was not visible on stderr: %s", stderr)
	}
	t.Log("25 warning calls and tools/list forwarded; stdout JSON-RPC only; findings visible on stderr")
}
