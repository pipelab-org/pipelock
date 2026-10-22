// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

func TestHTTPListener_LatePostRevocationKeepsResponseDirection(t *testing.T) {
	arrived := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "shared-session")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	}))
	t.Cleanup(upstream.Close)
	logger, events := newListenerEventLogger(t)
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		AuditLogger: logger, Scanner: testScannerForHTTP(t), ToolCfg: &tools.ToolScanConfig{Action: config.ActionBlock},
		// Pause after the response is read and validated, before delivery.
		// DELETE can then revoke the same legacy session deterministically.
		DoWRegisterSession: func(string) {
			close(arrived)
			<-release
		},
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	header := http.Header{"Mcp-Session-Id": {"shared-session"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/", strings.NewReader(upstreamStatusInitialize))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = header.Clone()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	type result struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			done <- result{err: requestErr}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, readErr := io.ReadAll(resp.Body)
		done <- result{status: resp.StatusCode, body: body, err: readErr}
	}()
	select {
	case <-arrived:
	case got := <-done:
		t.Fatalf("POST did not reach upstream: %+v", got)
	}
	deleted, _ := doListenerRequest(t, http.MethodDelete, baseURL+"/", "", header)
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status=%d", deleted.StatusCode)
	}
	releaseOnce.Do(func() { close(release) })
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.status == http.StatusOK || strings.Contains(string(got.body), `"result"`) {
		t.Fatalf("revoked POST relayed response: status=%d body=%s", got.status, got.body)
	}
	if strings.Count(events.String(), `"event":"blocked"`) != 1 || !strings.Contains(events.String(), `"direction":"response"`) || !strings.Contains(events.String(), `"block_class":"protective"`) {
		t.Fatalf("late refusal lost response direction: %s", events.String())
	}
}

func TestUpstreamClientErrorWriteState(t *testing.T) {
	for _, name := range []string{"active", "revoked", "escalated"} {
		t.Run(name, func(t *testing.T) {
			state := newMCPListenerTransientState()
			if name == "revoked" {
				state.revoke()
			}
			opts := MCPProxyOpts{}
			if name == "escalated" {
				opts.Rec = &mockRecorder{level: 1}
				opts.AdaptiveCfg = &config.AdaptiveEnforcement{Enabled: true, Levels: config.EscalationLevels{Elevated: config.EscalationActions{BlockAll: boolPtr(true)}}}
			}
			w := httptest.NewRecorder()
			reply := upstreamClientError{status: http.StatusUnauthorized, header: http.Header{"Www-Authenticate": {upstreamStatusChallenge}}, body: []byte("refusal")}
			ok, reason, detail := reply.writeIfActive(w, state, opts)
			if name != "escalated" && detail != "" {
				t.Fatalf("non-adaptive gate returned detail: %q", detail)
			}
			want := name == "active"
			if ok != want {
				t.Fatalf("write allowed=%v want=%v reason=%s", ok, want, reason)
			}
			if !want {
				if w.Body.Len() != 0 || len(w.Header()) != 0 {
					t.Fatalf("revoked state wrote upstream content: %v %s", w.Header(), w.Body.String())
				}
			} else if w.Code != http.StatusUnauthorized || w.Body.String() != "refusal" || w.Header().Get("Www-Authenticate") != upstreamStatusChallenge {
				t.Fatalf("active state did not relay: %d %v %s", w.Code, w.Header(), w.Body.String())
			}
		})
	}
}

func TestHTTPListener_ClientErrorHonorsLiveResponseGates(t *testing.T) {
	for _, gate := range []string{"identity", "kill switch"} {
		for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
			t.Run(gate+"/"+method, func(t *testing.T) {
				var changed atomic.Bool
				cfg := config.Defaults()
				ks := killswitch.New(cfg)
				const replyText = "upstream refusal after revocation"
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					changed.Store(true)
					if gate == "kill switch" {
						ks.SetAPI(true)
					}
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, replyText)
				}))
				t.Cleanup(upstream.Close)
				logger, events := newListenerEventLogger(t)
				baseURL, logBuf := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
					AuditLogger: logger, Scanner: testScannerForHTTP(t), KillSwitch: ks,
					ServerIdentityFn: func() ServerIdentity {
						if gate == "identity" && changed.Load() {
							return ServerIdentity{Refusal: identityRefusalText}
						}
						return ServerIdentity{Name: "vendor-indexer", PolicyName: "vendor-indexer", Binding: "binding", BindingMode: config.MCPAckBindingModeVerifiedLocalSession, Revision: "rev"}
					},
				})
				request := ""
				if method == http.MethodPost {
					request = upstreamStatusInitialize
				}
				header := http.Header{"Accept": {"text/event-stream"}}
				resp, body := doListenerRequest(t, method, baseURL+"/", request, header)
				if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), replyText) {
					t.Fatalf("revoked upstream content relayed: status=%d body=%s", resp.StatusCode, body)
				}
				if strings.Count(events.String(), `"event":"blocked"`) != 1 || !strings.Contains(events.String(), `"direction":"response"`) || !strings.Contains(events.String(), `"transport":"mcp_http_listener"`) {
					t.Fatalf("withheld response lost its canonical route: %s", events.String())
				}
				// The reason proves the request reached the upstream and the
				// live gate, not an earlier refusal, withheld the reply.
				wantReason := map[string]string{"identity": "upstream identity changed", "kill switch": "kill switch blocks responses"}[gate]
				if !changed.Load() || !strings.Contains(logBuf.String(), "reply withheld: "+wantReason) {
					t.Fatalf("upstream reached=%v log=%q, want withhold reason %q", changed.Load(), logBuf.String(), wantReason)
				}
			})
		}
	}
}
