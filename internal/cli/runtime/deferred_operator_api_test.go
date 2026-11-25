// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type taskGrantTestStore struct {
	session.Store
	keys chan string
}

func (s taskGrantTestStore) GetOrCreate(key string) session.Recorder {
	rec := s.Store.GetOrCreate(key)
	s.keys <- key
	return rec
}

func TestMCPOperatorAPIInstallsLiveTaskPermissionWithoutDefer(t *testing.T) {
	cfg := config.Defaults()
	cfg.SessionProfiling.Enabled = true
	cfg.KillSwitch.APIListen = "127.0.0.1:0"
	cfg.KillSwitch.APIToken = "operator-test-token"
	var sessions atomic.Pointer[proxy.SessionManager]
	manager := proxy.NewSessionManager(&cfg.SessionProfiling, nil, nil)
	defer manager.Close()
	sessions.Store(manager)
	var startup bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stop, err := startMCPOperatorAPI(ctx, cfg, nil, audit.NewNop(), &startup, &sessions)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	fields := strings.Fields(startup.String())
	if len(fields) < 6 {
		t.Fatalf("missing operator listener address: %q", startup.String())
	}
	baseURL := "http://" + fields[5]

	var delivered atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		delivered.Add(1)
		var frame struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}`, frame.ID)
	}))
	defer upstream.Close()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	in, send := io.Pipe()
	receive, out := io.Pipe()
	defer func() { _ = receive.Close() }()
	defer func() { _ = send.Close() }()
	store := taskGrantTestStore{Store: manager.AsStore(), keys: make(chan string, 1)}
	done := make(chan error, 1)
	const binding = "server-binding"
	go func() {
		err := mcp.RunHTTPProxy(ctx, in, out, io.Discard, upstream.URL, nil, mcp.MCPProxyOpts{
			Scanner: sc, Store: store, TaintCfg: &cfg.Taint, ServerBinding: binding, TaskOperatorAPI: true,
		})
		_ = out.CloseWithError(err)
		done <- err
	}()
	var key string
	select {
	case key = <-store.keys:
	case <-ctx.Done():
		t.Fatal("MCP bridge did not create an invocation")
	}
	rec := manager.SessionByKey(key)
	taskID := rec.TaskSnapshot().CurrentTaskID
	rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	const params = `{"name":"write_file","arguments":{"path":"/workspace/status.txt","content":"ready"}}`
	output := bufio.NewReader(receive)
	call := func(id int, args string) string {
		t.Helper()
		if _, err := fmt.Fprintf(send, "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":%s}\n", id, args); err != nil {
			t.Fatal(err)
		}
		line, err := output.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	// The digest is keyed per process, so the operator copies it from the refusal.
	refusal := call(1, params)
	if !strings.Contains(refusal, "task_approval_unavailable") || delivered.Load() != 0 {
		t.Fatalf("ungranted write delivered=%d response=%s", delivered.Load(), refusal)
	}
	_, digest, found := strings.Cut(refusal, "digest ")
	if !found || len(digest) < sha256.Size*2 {
		t.Fatalf("refusal carries no digest: %s", refusal)
	}
	action := session.TaskAction{Method: "tools/call", Destination: binding, Tool: "write_file", Digest: digest[:sha256.Size*2]}
	grant := struct {
		TaskID     string                 `json:"task_id"`
		Permission session.TaskPermission `json:"permission"`
	}{taskID, session.TaskPermission{Action: action, ExpiresAt: time.Now().Add(time.Hour)}}
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, token string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	path := "/api/v1/sessions/" + key + "/task"
	if status := request(http.MethodPost, path, ""); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated task status = %d", status)
	}
	if status := request(http.MethodPost, path, cfg.KillSwitch.APIToken); status != http.StatusNoContent {
		t.Fatalf("authenticated task status = %d", status)
	}
	if risk, task, matched := rec.TaskPolicySnapshot(key, action); !matched || risk.Level != session.TaintExternalHostile || task.CurrentTaskID != taskID {
		t.Fatalf("live recorder matched=%t, risk=%s, task=%s", matched, risk.Level, task.CurrentTaskID)
	}
	if reply := call(2, params); !strings.Contains(reply, `"result"`) || delivered.Load() != 1 {
		t.Fatalf("granted write delivered=%d response=%s", delivered.Load(), reply)
	}
	for n, changed := range []string{strings.Replace(params, "status.txt", "other.txt", 1), strings.Replace(params, "ready", "changed", 1)} {
		if reply := call(3+n, changed); !strings.Contains(reply, "task_approval_unavailable") || delivered.Load() != 1 {
			t.Fatalf("mismatched write delivered=%d response=%s", delivered.Load(), reply)
		}
	}
	_ = send.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func deferredOpTestManager(t *testing.T) *deferred.Manager {
	t.Helper()
	m := deferred.NewManager(deferred.Config{
		Enabled:              true,
		Timeout:              time.Hour,
		MaxPending:           8,
		MaxPendingPerSession: 8,
		MaxPendingBytes:      1 << 20,
		MaxCascadeDepth:      4,
	})
	if err := m.Hold(deferred.HeldAction{
		DeferID:   "0193defer00000000000000000001",
		ActionID:  "0193defer00000000000000000001",
		Surface:   deferred.SurfaceMCPStdio,
		Method:    "tools/call",
		Target:    "shell.exec",
		Reason:    "tool policy: defer",
		Authority: deferred.AuthoritySnapshot{SessionID: "sess-1"},
		Resolve:   func(deferred.Resolution) {},
	}); err != nil {
		t.Fatalf("seed hold: %v", err)
	}
	return m
}

// TestStartDeferredOperatorAPI_NoListenerWhenUnset proves the surface is not
// exposed (no listener started) when api_listen is unset, defer is disabled, or
// no live manager exists - and that the returned stop is a safe no-op.
func TestStartDeferredOperatorAPI_NoListenerWhenUnset(t *testing.T) {
	logger := audit.NewNop()
	cases := []struct {
		name string
		cfg  *config.Config
		mgr  *deferred.Manager
	}{
		{"api_listen unset", &config.Config{}, deferredOpTestManager(t)},
		{"nil manager", func() *config.Config {
			c := &config.Config{}
			c.KillSwitch.APIListen = "127.0.0.1:0"
			c.KillSwitch.APIToken = "t"
			return c
		}(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stop, err := startDeferredOperatorAPI(context.Background(), tc.cfg, tc.mgr, logger, io.Discard)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if stop == nil {
				t.Fatal("stop must be non-nil")
			}
			stop() // must not panic
		})
	}
}

// TestStartDeferredOperatorAPI_ServesDeferredRoutes proves the listener exposes
// the deferred list/approve/deny surface, wired to the live manager, and gates
// it behind the admin bearer token.
func TestStartDeferredOperatorAPI_ServesDeferredRoutes(t *testing.T) {
	const token = "op-token"
	testport.WithRetry(t, 1, func(addrs []string) error {
		return serveDeferredOperatorRoutes(t, token, addrs[0])
	})
}

func serveDeferredOperatorRoutes(t *testing.T, token, addr string) error {
	t.Helper()
	cfg := &config.Config{}
	cfg.KillSwitch.APIListen = addr
	cfg.KillSwitch.APIToken = token
	mgr := deferredOpTestManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, err := startDeferredOperatorAPI(ctx, cfg, mgr, audit.NewNop(), io.Discard)
	if err != nil {
		if stop != nil {
			stop()
		}
		return fmt.Errorf("start: %w", err)
	}
	defer stop()

	client := &http.Client{Timeout: 5 * time.Second}
	base := "http://" + addr
	get := func(t *testing.T, url string, auth bool) *http.Response {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, reqErr := client.Do(req)
		if reqErr != nil {
			t.Fatalf("GET %s: %v", url, reqErr)
		}
		return resp
	}

	// Wait until the listener is serving.
	testwait.For(t, 3*time.Second, func() bool {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/deferred", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, reqErr := client.Do(req)
		if reqErr != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "deferred operator API on %s", addr)

	// GET /api/v1/deferred returns the held action.
	resp := get(t, base+"/api/v1/deferred", true)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d body=%s", resp.StatusCode, body)
	}
	var list struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Count != 1 {
		t.Fatalf("count=%d, want 1", list.Count)
	}

	// Unauthenticated list is rejected.
	resp = get(t, base+"/api/v1/deferred", false)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth list status=%d, want 401", resp.StatusCode)
	}

	// deny resolves the held action via the operator surface.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v1/deferred/0193defer00000000000000000001/deny", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deny status=%d, want 200", resp.StatusCode)
	}
	if got := mgr.Snapshot(); len(got) != 0 {
		t.Fatalf("hold still held after deny: %d", len(got))
	}
	return nil
}

func TestStartDeferredOperatorAPI_UsesEnvAPIToken(t *testing.T) {
	token := "op-env-" + "val"
	t.Setenv(killswitch.EnvAPIToken, token)
	testport.WithRetry(t, 1, func(addrs []string) error {
		cfg := &config.Config{}
		cfg.KillSwitch.APIListen = addrs[0]
		mgr := deferredOpTestManager(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stop, err := startDeferredOperatorAPI(ctx, cfg, mgr, audit.NewNop(), io.Discard)
		if err != nil {
			if stop != nil {
				stop()
			}
			return fmt.Errorf("start: %w", err)
		}
		defer stop()
		client := &http.Client{Timeout: 5 * time.Second}
		base := "http://" + addrs[0]
		testwait.For(t, 3*time.Second, func() bool {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/deferred", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, reqErr := client.Do(req)
			if reqErr != nil {
				return false
			}
			_ = resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		}, "deferred operator API with env token on %s", addrs[0])
		return nil
	})
}

func TestStartDeferredOperatorAPI_MissingTokenFailsFast(t *testing.T) {
	t.Setenv(killswitch.EnvAPIToken, "")
	cfg := &config.Config{}
	cfg.KillSwitch.APIListen = "127.0.0.1:0"

	stop, err := startDeferredOperatorAPI(context.Background(), cfg, deferredOpTestManager(t), audit.NewNop(), io.Discard)
	if err == nil {
		stop()
		t.Fatal("expected missing token error, got nil")
	}
	if stop == nil {
		t.Fatal("stop must be non-nil on error")
	}
	stop()
}

// TestStartDeferredOperatorAPI_BindErrorIsFatal proves a bind conflict on
// api_listen returns an error (fail-fast) rather than silently continuing
// without an operator surface.
func TestStartDeferredOperatorAPI_BindErrorIsFatal(t *testing.T) {
	// Occupy a port, then point api_listen at it.
	occupied, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	cfg := &config.Config{}
	cfg.KillSwitch.APIListen = occupied.Addr().String()
	cfg.KillSwitch.APIToken = "t"

	stop, err := startDeferredOperatorAPI(context.Background(), cfg, deferredOpTestManager(t), audit.NewNop(), io.Discard)
	if err == nil {
		stop()
		t.Fatal("expected bind error on occupied port, got nil")
	}
	if stop == nil {
		t.Fatal("stop must be non-nil even on error")
	}
	stop() // no-op, must not panic
}
