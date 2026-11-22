// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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

func TestTaskPermissionAPIRejectsInvalidGrantsWithoutChangingTask(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	sm := NewSessionManager(&cfg.SessionProfiling, nil, nil)
	t.Cleanup(sm.Close)
	var manager atomic.Pointer[SessionManager]
	manager.Store(sm)
	const key = "verified-session"
	const token = "test-operator"
	const taskPath = "/api/v1/sessions/" + key + "/task"
	handler := NewSessionAPIHandler(SessionAPIOptions{SessionMgrPtr: &manager, APIToken: token})
	sess := sm.GetOrCreate(key)
	sess.BindTaskSubject(key)
	sess.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	taskID := sess.TaskSnapshot().CurrentTaskID
	action := session.TaskAction{Method: http.MethodPost, Destination: "http://peer.vendor.example/update", Digest: strings.Repeat("a", 64)}
	valid := session.TaskPermission{Action: action, ExpiresAt: time.Now().Add(time.Hour)}
	other := valid
	other.Action.Destination = "http://peer.vendor.example/notes"
	if err := sess.installTaskPermission(taskID, other); err != nil {
		t.Fatalf("seeding unrelated permission: %v", err)
	}
	storedPermissions := func() []session.TaskPermission {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return slices.Clone(sess.taskPermissions)
	}

	grantBody := func(t *testing.T, req taskRequest) string {
		t.Helper()
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	withoutDigest := valid
	withoutDigest.Action.Digest = ""
	expired := valid
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	for _, tc := range []struct {
		name, path, token, body, reason string
		status                          int
	}{
		{"wrong_token", taskPath, "other-operator", grantBody(t, taskRequest{TaskID: taskID, Permission: &valid}), "unauthorized", http.StatusUnauthorized},
		{"bad_json", taskPath, token, `{"permission":[]}`, "invalid JSON body", http.StatusBadRequest},
		{"task_id_without_permission", taskPath, token, grantBody(t, taskRequest{TaskID: taskID}), "task_id requires a permission", http.StatusBadRequest},
		{"grant_cannot_relabel", taskPath, token, grantBody(t, taskRequest{TaskID: taskID, Label: "replacement", Permission: &valid}), "a permission does not rotate or relabel the task", http.StatusBadRequest},
		{"session_missing", "/api/v1/sessions/missing/task", token, grantBody(t, taskRequest{TaskID: taskID, Permission: &valid}), "session not found", http.StatusNotFound},
		{"generation_missing", taskPath, token, grantBody(t, taskRequest{Permission: &valid}), "task generation does not match the current task", http.StatusConflict},
		{"digest_missing", taskPath, token, grantBody(t, taskRequest{TaskID: taskID, Permission: &withoutDigest}), "task permission requires an exact action and a future expiry", http.StatusBadRequest},
		{"expiry_in_past", taskPath, token, grantBody(t, taskRequest{TaskID: taskID, Permission: &expired}), "task permission requires an exact action and a future expiry", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := storedPermissions()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			handler.HandleTask(w, req)
			if w.Code != tc.status || strings.TrimSpace(w.Body.String()) != tc.reason {
				t.Errorf("status=%d body=%q, want %d with %q", w.Code, w.Body, tc.status, tc.reason)
			}
			if after := storedPermissions(); !slices.Equal(before, after) {
				t.Errorf("rejected request changed stored permissions: before=%+v after=%+v", before, after)
			}
			risk, current, matched := sess.TaskPolicySnapshot(key, action)
			if risk.Level != session.TaintExternalHostile || current.CurrentTaskID != taskID || matched {
				t.Errorf("rejected grant changed session: risk=%s task=%q matched=%t", risk.Level, current.CurrentTaskID, matched)
			}
		})
	}
}

func TestTaskPermissionCapacityAllowsReplacementAndPrunesExpiry(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	sm := NewSessionManager(&cfg.SessionProfiling, nil, nil)
	t.Cleanup(sm.Close)
	const subject = "bound-worker"
	sess := sm.GetOrCreate(subject)
	sess.BindTaskSubject(subject)
	sess.BindTaskSubject("different-worker")
	task := sess.TaskSnapshot()
	expires := time.Now().Add(time.Hour)

	grant := func(action int) session.TaskPermission {
		return session.TaskPermission{
			Action: session.TaskAction{
				Method: http.MethodPost, Destination: "http://peer.vendor.example/update", Digest: fmt.Sprintf("%064x", action),
			},
			ExpiresAt: expires,
		}
	}
	for index := range maxTaskPermissions {
		if err := sess.installTaskPermission(task.CurrentTaskID, grant(index)); err != nil {
			t.Fatalf("installing permission %d: %v", index, err)
		}
	}
	extra := grant(maxTaskPermissions)
	if err := sess.installTaskPermission(task.CurrentTaskID, extra); !errors.Is(err, errTaskPermissionCount) {
		t.Fatalf("installing beyond capacity: %v, want permission limit error", err)
	}
	if _, _, ok := sess.TaskPolicySnapshot(subject, extra.Action); ok {
		t.Fatal("over-capacity grant became active")
	}
	first := grant(0)
	first.ExpiresAt = expires.Add(time.Hour)
	if err := sess.installTaskPermission(task.CurrentTaskID, first); err != nil {
		t.Fatalf("replacing a grant at capacity: %v", err)
	}
	if _, _, ok := sess.TaskPolicySnapshot("different-worker", first.Action); ok {
		t.Fatal("rebinding the recorder gave a different worker the grant")
	}
	if _, _, ok := sess.TaskPolicySnapshot(subject, first.Action); !ok {
		t.Fatal("replacement grant did not remain active for the original worker")
	}

	sess.mu.Lock()
	count := len(sess.taskPermissions)
	index := slices.IndexFunc(sess.taskPermissions, func(p session.TaskPermission) bool { return p.Action == first.Action })
	if count != maxTaskPermissions || index < 0 {
		sess.mu.Unlock()
		t.Fatalf("replacement index=%d count=%d, want the same action and %d permissions", index, count, maxTaskPermissions)
	}
	if storedExpiry := sess.taskPermissions[index].ExpiresAt; !storedExpiry.Equal(first.ExpiresAt) {
		sess.mu.Unlock()
		t.Fatalf("replacement expiry=%v, want %v", storedExpiry, first.ExpiresAt)
	}
	sess.taskPermissions[index].ExpiresAt = time.Now().Add(-time.Hour)
	sess.mu.Unlock()
	if _, _, ok := sess.TaskPolicySnapshot(subject, first.Action); ok {
		t.Fatal("replacement action remained active after its stored entry was expired")
	}
	if err := sess.installTaskPermission(task.CurrentTaskID, extra); err != nil {
		t.Fatalf("install after expiry: %v", err)
	}
	if _, _, ok := sess.TaskPolicySnapshot(subject, extra.Action); !ok {
		t.Fatal("new grant did not occupy the expired grant's slot")
	}
}

type taskPromptWriter func([]byte) (int, error)

func (w taskPromptWriter) Write(p []byte) (int, error) { return w(p) }

type taskRequestReader func([]byte) (int, error)

func (r taskRequestReader) Read(p []byte) (int, error) { return r(p) }

func TestForwardTaskPermissionApprovalOutcomes(t *testing.T) {
	t.Parallel()
	const actor = "bound-worker"
	const target = "http://peer.vendor.example/update"
	const payload = "ready"
	for _, tc := range []struct {
		name, answer, reason string
		noChannel, nonTTY    bool
		timeout, rotate      bool
		badBody, trailer     bool
		wantCalls            int32
	}{
		{name: "unavailable", noChannel: true, reason: "task_approval_unavailable"},
		{name: "non_terminal", nonTTY: true, reason: "task_approval_unavailable"},
		{name: "declined", answer: "n\n", reason: "task_approval_denied"},
		{name: "timed_out", timeout: true, reason: "task_approval_timeout"},
		{name: "input_lost", reason: "task_approval_input_lost"},
		{name: "unconfirmed", answer: "y\n", reason: "task_approval_unconfirmed"},
		{name: "confirmed", wantCalls: 1},
		{name: "rotated_during_confirmation", rotate: true, reason: session.TaskApprovalStale},
		{name: "unreadable_body", badBody: true, reason: "task_action_unavailable"},
		{name: "unbound_trailer", trailer: true, reason: "task_action_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != payload || r.ContentLength != int64(len(payload)) {
					t.Errorf("upstream request body = %q, length = %d, error = %v", body, r.ContentLength, err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(upstream.Close)
			_, p, stop := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.SessionProfiling.Enabled = true
				cfg.RequestBodyScanning.Enabled = false
				cfg.KillSwitch.APIToken = "test-operator"
				cfg.Agents = map[string]config.AgentProfile{actor: {}}
			})
			t.Cleanup(stop)
			installForwardTestDialer(p, upstream.Listener.Addr().String())

			req := httptest.NewRequestWithContext(edition.WithAgentOverride(t.Context(), actor), http.MethodPost, target, strings.NewReader(payload))
			_, id := p.resolveAgentFromRequest(req)
			clientIP, _ := requestMeta(req)
			cfg := p.cfgPtr.Load()
			rec := p.sessionMgrPtr.Load().GetOrCreate(responseTaintSessionKey(cfg, id.Name, clientIP, id.Auth))
			observeHTTPResponseFindings(rec, cfg, "http://status.vendor.example/source", "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			if tc.badBody {
				req.Body = io.NopCloser(taskRequestReader(func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }))
			}
			if tc.trailer {
				req.Trailer = http.Header{"X-Summary": {"ready"}}
			}

			p.approver = nil
			if !tc.noChannel {
				var input io.Reader = strings.NewReader(tc.answer)
				output := io.Discard
				if tc.timeout || tc.rotate || tc.wantCalls == 1 {
					r, w := io.Pipe()
					t.Cleanup(func() {
						_ = w.Close()
						_ = r.Close()
					})
					input = r
					if !tc.timeout {
						output = taskPromptWriter(func(p []byte) (int, error) {
							if _, text, found := strings.Cut(string(p), "enter y "); found {
								challenge, _, _ := strings.Cut(text, ".")
								if tc.rotate {
									rec.BeginNewTask("rotated during approval")
								}
								_, err := io.WriteString(w, "y "+challenge+"\n")
								return len(p), err
							}
							return len(p), nil
						})
					}
				}
				p.approver = hitl.New(1, hitl.WithTerminal(!tc.nonTTY), hitl.WithInput(input), hitl.WithOutput(output))
				t.Cleanup(p.approver.Close)
			}

			var receipts *receiptProxyHelper
			if tc.name == "declined" {
				receipts = newReceiptProxyHelper(t)
				t.Cleanup(func() { _ = receipts.rec.Close() })
				p.receiptEmitterPtr.Store(receipts.emitter)
			}
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, req)
			wantStatus := http.StatusForbidden
			if tc.wantCalls == 1 {
				wantStatus = http.StatusNoContent
			}
			if w.Code != wantStatus || calls.Load() != tc.wantCalls || !strings.Contains(w.Body.String(), tc.reason) {
				t.Fatalf("status=%d upstream calls=%d body=%q, want status=%d calls=%d reason=%q",
					w.Code, calls.Load(), w.Body, wantStatus, tc.wantCalls, tc.reason)
			}
			if receipts != nil {
				if !strings.Contains(w.Body.String(), "an operator can grant this action") {
					t.Errorf("operator grant hint missing: %s", w.Body)
				}
				rec := receipts.requireReceipt(t, "taint_policy").ActionRecord
				if rec.Verdict != config.ActionBlock || rec.TaintDecisionReason != tc.reason {
					t.Errorf("receipt verdict=%q reason=%q, want block with %q", rec.Verdict, rec.TaintDecisionReason, tc.reason)
				}
			}
		})
	}
}

func TestForwardTaskPermissionRefusesRotationDuringRequestBinding(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	t.Cleanup(upstream.Close)
	_, p, stop := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.SessionProfiling.Enabled = true
		cfg.RequestBodyScanning.Enabled = false
	})
	t.Cleanup(stop)
	installForwardTestDialer(p, upstream.Listener.Addr().String())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://peer.vendor.example/update", nil)
	_, id := p.resolveAgentFromRequest(req)
	clientIP, _ := requestMeta(req)
	cfg := p.cfgPtr.Load()
	rec := p.sessionMgrPtr.Load().GetOrCreate(responseTaintSessionKey(cfg, firstNonEmptyString(id.Name, agentAnonymous), clientIP, id.Auth))
	observeHTTPResponseFindings(rec, cfg, "http://status.vendor.example/source", "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	req.Body = io.NopCloser(taskRequestReader(func([]byte) (int, error) {
		rec.BeginNewTask("rotated while reading")
		return 0, io.EOF
	}))
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), session.TaskApprovalStale) || calls.Load() != 0 {
		t.Fatalf("status=%d upstream calls=%d body=%q, want stale task refusal with no upstream call", w.Code, calls.Load(), w.Body)
	}
}

func TestForwardTaskPermissionAtReceiptConfirmation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		rotate bool
		status int
		calls  int32
		reason string
	}{
		{name: "task_changed", rotate: true, status: http.StatusForbidden, reason: session.TaskApprovalStale},
		{name: "grant_current", status: http.StatusNoContent, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const actor = "bound-worker"
			const target = "http://peer.vendor.example/update"
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(upstream.Close)
			_, p, stop := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.SessionProfiling.Enabled = true
				cfg.FlightRecorder.RequireReceipts = true
				cfg.Agents = map[string]config.AgentProfile{actor: {}}
			})
			t.Cleanup(stop)
			p.approver = nil
			installForwardTestDialer(p, upstream.Listener.Addr().String())
			receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
			t.Cleanup(func() { _ = receipts.rec.Close() })
			if err := receipts.emitter.EmitSessionOpen(); err != nil {
				t.Fatal(err)
			}
			p.receiptEmitterPtr.Store(receipts.emitter)

			req := httptest.NewRequestWithContext(edition.WithAgentOverride(t.Context(), actor), http.MethodPost, target, nil)
			_, id := p.resolveAgentFromRequest(req)
			if id.Auth != envelope.ActorAuthBound {
				t.Fatalf("actor auth = %s, want bound", id.Auth)
			}
			clientIP, _ := requestMeta(req)
			cfg := p.cfgPtr.Load()
			rec := p.sessionMgrPtr.Load().GetOrCreate(responseTaintSessionKey(cfg, id.Name, clientIP, id.Auth))
			observeHTTPResponseFindings(rec, cfg, "http://status.vendor.example/source", "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			rec.BindTaskSubject("forward:" + actor)
			responseencoding.RequestIdentity(req.Header)
			if err := rec.installTaskPermission(rec.TaskSnapshot().CurrentTaskID, session.TaskPermission{
				Action: forwardRequestTaskAction(req, nil), ExpiresAt: time.Now().Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}

			syncStarted := make(chan struct{})
			releaseSync := make(chan struct{})
			release := sync.OnceFunc(func() { close(releaseSync) })
			defer release()
			var firstSync sync.Once
			receipts.rec.SetSyncForTest(func(f *os.File) error {
				firstSync.Do(func() {
					close(syncStarted)
					<-releaseSync
				})
				return f.Sync()
			})
			w := httptest.NewRecorder()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				p.handleForwardHTTP(w, req)
			}()
			select {
			case <-syncStarted:
			case <-finished:
				t.Fatalf("request returned before confirmation: status=%d body=%q", w.Code, w.Body)
			case <-time.After(5 * time.Second):
				t.Fatal("required receipt did not reach confirmation")
			}
			var rotatedTaskID string
			if tc.rotate {
				rec.BeginNewTask("next task")
				rotatedTaskID = rec.TaskSnapshot().CurrentTaskID
			}
			release()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not finish after confirmation")
			}

			if w.Code != tc.status || calls.Load() != tc.calls || !strings.Contains(w.Body.String(), tc.reason) {
				t.Fatalf("status=%d upstream calls=%d body=%q, want status=%d calls=%d reason=%q",
					w.Code, calls.Load(), w.Body, tc.status, tc.calls, tc.reason)
			}
			chain := receipts.findReceipts(t)
			if len(chain) != 3 {
				t.Fatalf("receipt count=%d, want session_open plus one intent and one outcome", len(chain))
			}
			if verified := receipt.VerifyChain(chain, receipts.pubHex); !verified.Valid {
				t.Fatalf("verify receipts: %s", verified.Error)
			}
			intent, outcome := chain[1].ActionRecord, chain[2].ActionRecord
			if intent.DecisionPhase != receipt.DecisionPhaseIntent || intent.Verdict != config.ActionAllow ||
				intent.TaintDecisionReason != session.TaskPermissionGranted ||
				outcome.DecisionPhase != receipt.DecisionPhaseOutcome || outcome.ActionID != intent.ActionID ||
				w.Header().Get(blockreason.HeaderRecordedReceipt) != intent.ActionID {
				t.Fatalf("expected a granted intent and linked outcome, got intent=%+v outcome=%+v", intent, outcome)
			}
			if tc.rotate {
				if outcome.Verdict != config.ActionBlock || outcome.TaintDecision != session.PolicyBlock.String() ||
					outcome.TaintDecisionReason != session.TaskApprovalStale ||
					outcome.Pattern != receiptOutcomePattern("403", 0, session.TaskApprovalStale) {
					t.Fatalf("expected a blocked stale-task outcome, got %+v", outcome)
				}
				// The refusal records the task that made the admission stale.
				if outcome.SessionTaskID != rotatedTaskID || outcome.SessionTaskID == intent.SessionTaskID {
					t.Fatalf("stale outcome task=%q intent task=%q, want rotated task %q", outcome.SessionTaskID, intent.SessionTaskID, rotatedTaskID)
				}
			} else if outcome.Verdict != config.ActionAllow || outcome.Pattern != receiptOutcomePattern("204", 0, "complete") {
				t.Fatalf("expected a successful outcome, got %+v", outcome)
			}
		})
	}
}

func TestForwardTaskReleaseRequiresCurrentGrant(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	sm := NewSessionManager(&cfg.SessionProfiling, nil, nil)
	t.Cleanup(sm.Close)
	const actor = "worker"
	rec := sm.GetOrCreate(actor)
	rec.BindTaskSubject(actor)
	task := forwardTaskAction{subject: actor, action: session.TaskAction{
		Method: http.MethodPost, Destination: "http://peer.vendor.example/update", Digest: strings.Repeat("a", 64),
	}}
	generation := rec.TaskSnapshot()
	if err := rec.installTaskPermission(generation.CurrentTaskID, session.TaskPermission{
		Action: task.action, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, reason string
		rec          session.Recorder
		want         bool
	}{
		{"active_grant", session.TaskPermissionGranted, rec, true},
		{"grant_without_recorder", session.TaskPermissionGranted, nil, false},
		{"approval_without_recorder", session.TaskApprovalGranted, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision := taintDecision{Task: generation, Result: session.PolicyDecisionResult{Reason: tc.reason}}
			if got := forwardTaskAdmissionCurrent(tc.rec, task, decision); got != tc.want {
				t.Errorf("release permitted=%t, want %t", got, tc.want)
			}
		})
	}
	rec.mu.Lock()
	rec.taskPermissions[0].ExpiresAt = time.Now().Add(-time.Hour)
	rec.mu.Unlock()
	decision := taintDecision{Task: generation, Result: session.PolicyDecisionResult{Reason: session.TaskPermissionGranted}}
	if forwardTaskAdmissionCurrent(rec, task, decision) {
		t.Fatal("expired task grant remained eligible for release")
	}
}

// A forward request whose required receipt is still waiting for a scan slot
// never reaches the upstream once its context ends. A client that left gets
// the ordinary cancellation answer; a cancellation Pipelock made itself, such
// as a revoked license, stays a block. Neither case marks the emitter
// unhealthy.
func TestForwardRequiredReceiptQueuedScanCancellation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		cause  error
		status int
		body   string
	}{
		{name: "client_gone", cause: context.Canceled, status: http.StatusServiceUnavailable, body: clientCanceledStatusText},
		{name: "license_revoked", cause: errAgentLicenseRevoked, status: http.StatusForbidden, body: "receipt emission failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(upstream.Close)
			_, p, stop := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = true
			})
			t.Cleanup(stop)
			installForwardTestDialer(p, upstream.Listener.Addr().String())

			sc := scanner.MustNew(config.Defaults())
			t.Cleanup(sc.Close)
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, priv)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rec.Close() })
			emitter := receipt.NewEmitter(receipt.EmitterConfig{
				Recorder: rec, PrivKey: priv, ConfigHash: coverageTestConfigHash,
				Principal: coverageTestPrincipal, Actor: coverageTestActor, Metrics: p.metrics,
			})
			if err := emitter.EmitSessionOpen(); err != nil {
				t.Fatal(err)
			}
			p.receiptEmitterPtr.Store(emitter)

			holdReceiptScanSlots(t, rec)
			queued := waitForQueuedReceiptScan(t, rec)
			reqCtx, cancelReq := context.WithCancelCause(t.Context())
			defer cancelReq(nil)
			req := httptest.NewRequestWithContext(reqCtx, http.MethodPost, "http://peer.vendor.example/update", nil)
			w := httptest.NewRecorder()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				p.handleForwardHTTP(w, req)
			}()
			select {
			case <-queued:
			case <-finished:
				t.Fatalf("request finished before its receipt scan queued: status=%d body=%q", w.Code, w.Body)
			case <-time.After(5 * time.Second):
				t.Fatal("receipt scan never queued for a slot")
			}
			cancelReq(tc.cause)
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("canceled request stayed queued for a receipt scan slot")
			}
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.body) || calls.Load() != 0 {
				t.Fatalf("status=%d body=%q upstream calls=%d, want status=%d body containing %q and no upstream call",
					w.Code, w.Body, calls.Load(), tc.status, tc.body)
			}
			if err := emitter.HealthError(); err != nil {
				t.Fatalf("cancellation changed emitter health: %v", err)
			}
			assertMetricsNotContain(t, p.metrics, `pipelock_required_receipt_blocks_total{reason="emit_error",transport="forward"} 1`)
		})
	}
}

var slotHoldProducer = receiptcontent.Register(receiptcontent.Schema{Kind: "pipelock.test.proxy_scan_slot_hold.v1"})

// heldScanContext parks a receipt scan just after it takes a recorder slot and
// reports that it holds one.
type heldScanContext struct {
	context.Context
	holding chan<- struct{}
	release <-chan struct{}
}

func (ctx heldScanContext) Err() error {
	select {
	case ctx.holding <- struct{}{}:
	default:
	}
	<-ctx.release
	return ctx.Context.Err()
}

// holdReceiptScanSlots occupies every receipt scan slot of rec until the test
// ends, so the next scan has to queue.
func holdReceiptScanSlots(t *testing.T, rec *recorder.Recorder) {
	t.Helper()
	slots := runtime.GOMAXPROCS(0)
	holding := make(chan struct{}, slots)
	release := make(chan struct{})
	var done sync.WaitGroup
	for range slots {
		done.Go(func() {
			_, _, _ = rec.ScanReceiptContent(heldScanContext{Context: t.Context(), holding: holding, release: release}, slotHoldProducer, nil)
		})
	}
	t.Cleanup(func() {
		close(release)
		done.Wait()
	})
	timeout := time.After(5 * time.Second)
	for range slots {
		select {
		case <-holding:
		case <-timeout:
			t.Fatal("receipt scan slots were not all held")
		}
	}
}

// waitForQueuedReceiptScan installs a wait hook on rec and returns a channel
// that receives once a scan has found every slot taken.
func waitForQueuedReceiptScan(t *testing.T, rec *recorder.Recorder) <-chan struct{} {
	t.Helper()
	queued := make(chan struct{}, 1)
	rec.SetContentScanWaitForTest(func() {
		select {
		case queued <- struct{}{}:
		default:
		}
	})
	t.Cleanup(func() { rec.SetContentScanWaitForTest(nil) })
	return queued
}
