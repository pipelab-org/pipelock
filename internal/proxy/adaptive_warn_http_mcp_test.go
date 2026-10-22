// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestAdaptiveMCPHTTPWarningsReloadAndSharedProxy(t *testing.T) {
	cfg := config.Defaults()
	cfg.SessionProfiling.Enabled = true
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.ApplyDefaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Coordination marker", Regex: `coordination-marker`, Severity: config.SeverityLow})
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
	defer sm.Close()
	var input atomic.Pointer[mcp.InputScanConfig]
	input.Store(&mcp.InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock})
	var adaptive atomic.Pointer[config.AdaptiveEnforcement]
	adaptive.Store(&cfg.AdaptiveEnforcement)
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var frame struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, frame.ID)
	}))
	defer upstream.Close()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- mcp.RunHTTPListenerProxy(ctx, ln, upstream.URL, io.Discard, mcp.MCPProxyOpts{
			Scanner: sc, Store: sm.AsStore(), InputCfgFn: input.Load, AdaptiveCfgFn: adaptive.Load,
			// This is a trusted authentication fixture. Production resolvers must
			// verify a credential before supplying this identity.
			ListenerPrincipalResolver: func(r *http.Request) (mcp.ListenerPrincipal, error) {
				return mcp.ListenerPrincipal{Provider: "test", Subject: r.Header.Get("X-Test-Subject")}, nil
			},
		})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := &http.Client{Timeout: 5 * time.Second}
	send := func(subject, msg, method string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+ln.Addr().String()+"/", strings.NewReader(msg))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		// Matches internal/mcp's currentMCPVersion and Streamable HTTP contract.
		req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", method)
		if method == "tools/call" {
			req.Header.Set("Mcp-Name", "coordinate")
		}
		req.Header.Set("X-Test-Subject", subject)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	const warning = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coordinate","arguments":{"text":"coordination-marker"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	const clean = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	checkAllowed := func(subject, msg, method string) {
		t.Helper()
		if status, body := send(subject, msg, method); status != http.StatusOK || strings.Contains(body, `"error"`) {
			t.Fatalf("expected allowed: status=%d body=%s", status, body)
		}
	}
	for range 25 {
		checkAllowed("first", warning, "tools/call")
	}
	checkAllowed("first", clean, "tools/list")
	checkAllowed("second", clean, "tools/list")
	if snapshots := sm.Snapshot(); len(snapshots) != 2 {
		t.Fatalf("shared proxy sessions=%+v", snapshots)
	} else {
		for _, snap := range snapshots {
			if snap.ThreatScore != 0 || snap.BlockAll {
				t.Fatalf("warning created enforcement: %+v", snap)
			}
		}
	}
	// No-change reload retains the same recorder without manufacturing points.
	unchanged := cfg.AdaptiveEnforcement
	adaptive.Store(&unchanged)
	sm.UpdateConfig(&cfg.SessionProfiling, &unchanged, nil)
	checkAllowed("first", warning, "tools/call")
	// Changing the source to block is effective immediately, fails closed, and
	// does not quarantine the second authenticated session.
	input.Store(&mcp.InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock})
	before := hits.Load()
	if _, body := send("first", warning, "tools/call"); !strings.Contains(body, `"error"`) {
		t.Fatalf("explicit block allowed: %s", body)
	}
	if hits.Load() != before {
		t.Fatal("explicit block reached upstream")
	}
	checkAllowed("second", clean, "tools/list")
	// Downgrade and adaptive disable take effect on retained state. The parser
	// floor stays fail-closed independently of warn and adaptive settings.
	disabled := unchanged
	disabled.Enabled = false
	adaptive.Store(&disabled)
	sm.UpdateConfig(&cfg.SessionProfiling, &disabled, nil)
	input.Store(&mcp.InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock})
	checkAllowed("first", warning, "tools/call")
	if _, body := send("first", `{"jsonrpc":"2.0","id":3,"method":42}`, "tools/call"); !strings.Contains(body, `"error"`) {
		t.Fatalf("malformed method allowed: %s", body)
	}
	t.Log("25 warnings, no-change reload, independent sessions, explicit block, downgrade, malformed method: PASS")
}
