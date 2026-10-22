// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// webhookRecorder captures every body POSTed to it.
type webhookRecorder struct {
	mu     sync.Mutex
	bodies []string
}

// webhookRecorderDelay holds each delivery open past the point where the proxy
// command returns, so an event only reaches the recorder if the emitter's Close
// waits for the in-flight send. Without it the sink wins the race by chance and
// a missing Close would go unnoticed.
const webhookRecorderDelay = 250 * time.Millisecond

func (r *webhookRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	time.Sleep(webhookRecorderDelay)
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.bodies = append(r.bodies, string(body))
	r.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (r *webhookRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

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

// TestMCPProxyDeliversBlockedEventToWebhook proves a wrapper honors emit:
// a blocked tool call reaches the configured webhook, and the event carries
// the finding rather than the secret that triggered it.
func TestMCPProxyDeliversBlockedEventToWebhook(t *testing.T) {
	recorder := &webhookRecorder{}
	srv := httptest.NewServer(recorder)
	defer srv.Close()

	configPath := writeMCPEmitConfig(t, fmt.Sprintf(`emit:
  instance_id: mcp-emit-test
  webhook:
    url: %q
    min_severity: info
`, srv.URL))

	// Built at runtime so the repository holds no credential-shaped literal.
	secret := "AKIA" + "Z7VRSQ5TJN2XMPLQ"
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"runtime-test","version":"0"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"play_game","arguments":{"player":"` + secret + `"}}}`,
	}, "\n") + "\n"

	stdout, stderr, err := runMCPProxyCommandWithInput(t, mcpEmitProxyArgs(configPath), input)
	if err != nil {
		t.Fatalf("mcp proxy: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, `"id":2`) || !strings.Contains(stdout, `"error"`) {
		t.Fatalf("expected tool call 2 to be blocked, stdout:\n%s", stdout)
	}

	// The emitter is closed when the command returns, and the webhook sink
	// drains its queue on Close, so delivery has completed by now.
	bodies := recorder.snapshot()
	if len(bodies) == 0 {
		t.Fatalf("webhook received no events; emit section was ignored\nstderr:\n%s", stderr)
	}
	var sawBlocked bool
	for _, body := range bodies {
		if strings.Contains(body, secret) {
			t.Fatalf("webhook event leaked the blocked secret: %s", body)
		}
		if strings.Contains(body, `"pipelock_instance":"mcp-emit-test"`) && strings.Contains(body, `"type":"blocked"`) {
			sawBlocked = true
		}
	}
	if !sawBlocked {
		t.Fatalf("no blocked event with the configured instance; got:\n%s", strings.Join(bodies, "\n"))
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
