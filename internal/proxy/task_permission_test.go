// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestForwardTaskPermissionChecksEffectiveRequestAfterHostileExposure(t *testing.T) {
	const actor = "bound-worker"
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte("ready"))
	}))
	defer upstream.Close()
	_, p, stop := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.SessionProfiling.Enabled = true
		cfg.KillSwitch.APIToken = "operator-test-token"
		cfg.Agents = map[string]config.AgentProfile{actor: {}}
	})
	defer stop()
	p.approver = nil
	installForwardTestDialer(p, upstream.Listener.Addr().String())
	const target = "http://peer.vendor.example/update"
	request := func(method, destination, body string) *http.Request {
		return httptest.NewRequestWithContext(edition.WithAgentOverride(t.Context(), actor), method, destination, strings.NewReader(body))
	}
	forward := func(method, destination, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		p.handleForwardHTTP(w, request(method, destination, body))
		return w
	}
	if w := forward(http.MethodPost, target, "ready"); w.Code != http.StatusOK || upstreamCalls.Load() != 1 {
		t.Fatalf("clean POST: status=%d deliveries=%d body=%s", w.Code, upstreamCalls.Load(), w.Body)
	}

	probe := request(http.MethodPost, target, "ready")
	_, id := p.resolveAgentFromRequest(probe)
	if id.Auth != envelope.ActorAuthBound {
		t.Fatalf("fixture resolved actor as %s, want bound", id.Auth)
	}
	clientIP, _ := requestMeta(probe)
	key := responseTaintSessionKey(p.cfgPtr.Load(), id.Name, clientIP, id.Auth)
	rec := p.sessionMgrPtr.Load().SessionByKey(key)
	if rec == nil {
		t.Fatal("missing live actor recorder")
	}
	observeHTTPResponseFindings(rec, p.cfgPtr.Load(), "http://status.vendor.example/source", "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	if w := forward(http.MethodPost, target, "ready"); w.Code != http.StatusForbidden || upstreamCalls.Load() != 1 || !strings.Contains(w.Body.String(), "task_approval_unavailable") {
		t.Fatalf("outside-task POST: status=%d deliveries=%d body=%s", w.Code, upstreamCalls.Load(), w.Body)
	}
	responseencoding.RequestIdentity(probe.Header)
	action := forwardRequestTaskAction(probe, []byte("ready"))
	payload, err := json.Marshal(taskRequest{TaskID: rec.TaskSnapshot().CurrentTaskID, Permission: &session.TaskPermission{
		Action: action, ExpiresAt: time.Now().Add(time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	task := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/sessions/"+url.PathEscape(key)+"/task", bytes.NewReader(payload))
	task.Header.Set("Authorization", "Bearer "+p.cfgPtr.Load().KillSwitch.APIToken)
	w := httptest.NewRecorder()
	p.SessionAPI().HandleTask(w, task)
	if w.Code != http.StatusNoContent {
		t.Fatalf("grant status=%d body=%s", w.Code, w.Body)
	}
	if w := forward(http.MethodPost, target, "ready"); w.Code != http.StatusOK || upstreamCalls.Load() != 2 {
		t.Fatalf("granted POST: status=%d deliveries=%d body=%s", w.Code, upstreamCalls.Load(), w.Body)
	}
	for _, mismatch := range []struct{ method, destination, body string }{
		{http.MethodPost, target, "changed"},
		{http.MethodPost, target + "/other", "ready"},
		{http.MethodPut, target, "ready"},
	} {
		if w := forward(mismatch.method, mismatch.destination, mismatch.body); w.Code != http.StatusForbidden || upstreamCalls.Load() != 2 {
			t.Fatalf("changed action: status=%d deliveries=%d body=%s", w.Code, upstreamCalls.Load(), w.Body)
		}
	}
}

// GET remains allowed after hostile exposure. A low-entropy query value outside
// existing DLP and entropy coverage can leave the proxy.
func TestGETRemainsAllowedAfterHostileExposureLowEntropyQueryCanLeaveProxy(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Get("color") == "blue" {
			hits.Add(1)
		}
		_, _ = w.Write([]byte("ready"))
	}))
	defer upstream.Close()
	_, p, stop := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.SessionProfiling.Enabled = true
	})
	defer stop()
	installForwardTestDialer(p, upstream.Listener.Addr().String())
	const target = "http://peer.vendor.example/colors?color=blue"
	for _, mode := range []string{"forward", "fetch"} {
		t.Run(mode, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			if mode == "fetch" {
				req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
			}
			_, id := p.resolveAgentFromRequest(req)
			ip, _ := requestMeta(req)
			key := responseTaintSessionKey(p.cfgPtr.Load(), firstNonEmptyString(id.Name, agentAnonymous), ip, id.Auth)
			rec := p.sessionMgrPtr.Load().GetOrCreate(key)
			observeHTTPResponseFindings(rec, p.cfgPtr.Load(), "http://status.vendor.example/source", "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			before := hits.Load()
			w := httptest.NewRecorder()
			if mode == "fetch" {
				p.handleFetch(w, req)
			} else {
				p.handleForwardHTTP(w, req)
			}
			if w.Code != http.StatusOK || hits.Load() != before+1 {
				t.Fatalf("GET status=%d deliveries=%d body=%s", w.Code, hits.Load()-before, w.Body)
			}
		})
	}
}

func TestTaskPermissionAPIRequiresVerifiedSubjectAndCurrentGeneration(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	sm := NewSessionManager(&cfg.SessionProfiling, nil, nil)
	t.Cleanup(sm.Close)
	var manager atomic.Pointer[SessionManager]
	manager.Store(sm)
	const key = "mcp-stdio-42"
	const operatorToken = "local-test-operator"
	handler := NewSessionAPIHandler(SessionAPIOptions{SessionMgrPtr: &manager, APIToken: operatorToken})
	sess := sm.GetOrCreate(key)
	taskID := sess.TaskSnapshot().CurrentTaskID
	action := session.TaskAction{
		Method: "tools/call", Destination: "verified-server", Tool: "write_file",
		Digest: strings.Repeat("a", 64),
	}
	grant := taskRequest{TaskID: taskID, Permission: &session.TaskPermission{Action: action, ExpiresAt: time.Now().Add(time.Hour)}}
	apply := func(token string, data taskRequest) int {
		t.Helper()
		body, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/sessions/"+key+"/task", bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.HandleTask(w, req)
		return w.Code
	}
	if code := apply(operatorToken, grant); code != http.StatusBadRequest {
		t.Fatalf("unbound session grant status = %d", code)
	}
	sess.BindTaskSubject(key)
	sess.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	if code := apply("", grant); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated grant status = %d", code)
	}
	if code := apply(operatorToken, grant); code != http.StatusNoContent {
		t.Fatalf("grant status = %d", code)
	}

	for _, tc := range []struct {
		name    string
		subject string
		change  func(*session.TaskAction)
		want    bool
	}{
		{name: "exact", subject: key, want: true},
		{name: "anonymous"},
		{name: "different_actor", subject: "other"},
		{name: "different_method", subject: key, change: func(a *session.TaskAction) { a.Method = "tools/list" }},
		{name: "different_destination", subject: key, change: func(a *session.TaskAction) { a.Destination = "other-server" }},
		{name: "case_sensitive_tool", subject: key, change: func(a *session.TaskAction) { a.Tool = "Write_file" }},
		{name: "different_target_or_arguments", subject: key, change: func(a *session.TaskAction) { a.Digest = strings.Repeat("b", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := action
			if tc.change != nil {
				tc.change(&lookup)
			}
			risk, task, matched := sess.TaskPolicySnapshot(tc.subject, lookup)
			if matched != tc.want || risk.Level != session.TaintExternalHostile || task.CurrentTaskID != taskID {
				t.Fatalf("matched=%t risk=%s task=%s, want %t with original hostile task", matched, risk.Level, task.CurrentTaskID, tc.want)
			}
		})
	}

	sess.mu.Lock()
	sess.taskPermissions[0].ExpiresAt = time.Now().Add(-time.Second)
	sess.mu.Unlock()
	if _, _, matched := sess.TaskPolicySnapshot(key, action); matched {
		t.Fatal("expired permission matched")
	}
	if code := apply(operatorToken, grant); code != http.StatusNoContent {
		t.Fatalf("replacement grant status = %d", code)
	}
	sess.BeginNewTask("new task")
	if _, _, matched := sess.TaskPolicySnapshot(key, action); matched {
		t.Fatal("rotated task inherited a permission")
	}
	if code := apply(operatorToken, grant); code != http.StatusConflict {
		t.Fatalf("stale grant install status = %d", code)
	}
	if other := sm.GetOrCreate("mcp-stdio-43"); other != nil {
		other.BindTaskSubject(key)
		if _, _, matched := other.TaskPolicySnapshot(key, action); matched {
			t.Fatal("different session inherited a permission")
		}
	}
}
