// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testport"
)

func TestMCPProxyCmdAuditModeStartupWarning(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{name: "omitted", yaml: "version: 1\nmode: balanced\n", want: false},
		{name: "enforce", yaml: "version: 1\nmode: balanced\nenforce: true\n", want: false},
		{name: "audit", yaml: "version: 1\nmode: balanced\nenforce: false\n", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRuntimeAuditConfig(t, tc.yaml)
			cmd := mcpProxyCmd()
			cmd.SilenceUsage = true
			cmd.SetArgs([]string{"--config", path, "--listen", "127.0.0.1:0", "--upstream", "ws://vendor.example/mcp"})
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "--listen with WebSocket upstream") {
				t.Fatalf("err = %v\n%s", err, out.String())
			}
			if strings.Contains(out.String(), mcpRequestAuditModeWarning) != tc.want {
				t.Fatalf("warning present=%t want=%t\n%s", strings.Contains(out.String(), mcpRequestAuditModeWarning), tc.want, out.String())
			}
		})
	}
}

func TestServerMCPListenerAuditModeReloads(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) (runErr error) {
		fetchAddr, mcpAddr := addrs[0], addrs[1]
		var hits atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}))
		defer upstream.Close()
		cfgPath := writeServerTestConfig(t, fmt.Sprintf(`version: 1
mode: balanced
enforce: false
mcp_tool_policy:
  enabled: true
  action: block
  rules:
    - name: probe
      tool_pattern: "^audit_probe$"
      action: block
fetch_proxy:
  listen: %q
  timeout_seconds: 5
logging:
  format: json
  output: stdout
`, fetchAddr))
		s, buf := newTestServerForStart(t, func(o *ServerOpts) {
			o.ConfigFile = cfgPath
			o.Listen = fetchAddr
			o.ListenChanged = true
			o.MCPListen = mcpAddr
			o.MCPUpstream = upstream.URL
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errCh := make(chan error, 1)
		go func() {
			defer close(errCh)
			errCh <- s.Start(ctx)
		}()
		defer func() {
			cancel()
			_ = s.Shutdown(context.Background())
			stopErr := <-errCh
			if runErr == nil && stopErr != nil && !errors.Is(stopErr, context.Canceled) {
				runErr = fmt.Errorf("listener stop: %w", stopErr)
			}
		}()
		if err := waitForPortOrCommandExitResult(mcpAddr, errCh, buf, upstream); err != nil {
			return err
		}
		if !buf.contains(mcpRequestAuditModeWarning) {
			t.Fatalf("listener startup missing audit warning:\n%s", buf.String())
		}
		body := postRuntimeAuditProbe(t, mcpAddr)
		if hits.Load() != 1 || strings.Contains(body, `"error"`) {
			t.Fatalf("audit start hits=%d body=%s", hits.Load(), body)
		}
		enforcing := s.proxy.CurrentConfig().Clone()
		on := true
		enforcing.Enforce = &on
		if err := reloadListenerStateToken(s, enforcing); err != nil {
			t.Fatalf("reload enforce: %v", err)
		}
		refused := postRuntimeAuditProbe(t, mcpAddr)
		if hits.Load() != 1 || !strings.Contains(refused, `"error"`) {
			t.Fatalf("reload to enforce hits=%d body=%s", hits.Load(), refused)
		}
		observing := s.proxy.CurrentConfig().Clone()
		off := false
		observing.Enforce = &off
		// Reload refuses to turn enforcement off. The listener keeps the
		// enforced posture instead of observing the downgrade.
		if err := reloadListenerStateToken(s, observing); err == nil || !strings.Contains(err.Error(), "enforce disabled") {
			t.Fatalf("reload audit: %v", err)
		}
		stillRefused := postRuntimeAuditProbe(t, mcpAddr)
		if hits.Load() != 1 || !strings.Contains(stillRefused, `"error"`) {
			t.Fatalf("downgrade rejected hits=%d body=%s", hits.Load(), stillRefused)
		}
		return nil
	})
}

func writeRuntimeAuditConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := t.TempDir() + "/pipelock.yaml"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func postRuntimeAuditProbe(t *testing.T, addr string) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"audit_probe","arguments":{"text":"hello"}}}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
