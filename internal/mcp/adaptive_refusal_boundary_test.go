// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// The caller-visible answer on the request whose finding crosses block_all.
// A server response no longer scores, so it cannot be that finding. The
// crossing finding is the agent's own request. JSON POST carries it in a
// header; GET SSE carries the same header and never opens a response stream,
// so both wires refuse before any SSE framing exists.
func TestAdaptiveUniformRefusalMCPListenerThresholdDelivery(t *testing.T) {
	for _, wire := range []string{"json", "sse"} {
		t.Run(wire, func(t *testing.T) {
			rec := &listenerDiagnosisRecorder{}
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				request, _ := io.ReadAll(r.Body)
				if bytes.Contains(request, []byte(`"initialize"`)) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"t","version":"1"}}}`)
					return
				}
				t.Errorf("crossing %s request reached upstream: %s", wire, request)
				w.WriteHeader(http.StatusBadRequest)
			}))
			t.Cleanup(upstream.Close)
			cfg := adaptiveCfgEnabled()
			cfg.EscalationThreshold = session.SignalPoints[session.SignalBlock]
			cfg.Levels.Elevated.BlockAll = boolPtr(true)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t), Store: &singleRecorderStore{rec: rec}, AdaptiveCfg: cfg, listenerStateTokenRequired: boolPtr(true)})
			token := listenerSetupToken(t, baseURL)
			before := upstreamCalls.Load()
			header := http.Header{listenerSessionTokenHeader: {token}, "Authorization": {"Bearer " + mcpSyntheticAWSAccessKey()}}
			method, request, wantID := http.MethodPost, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`, "2"
			if wire == "sse" {
				method, request, wantID = http.MethodGet, "", "null"
				header.Set("Accept", "text/event-stream")
			}
			resp, body := doListenerRequest(t, method, baseURL+"/", request, header)
			if rec.EscalationLevel() != 1 || rec.ThreatScore() != session.SignalPoints[session.SignalBlock] {
				t.Fatalf("agent finding did not raise level: level=%d score=%v", rec.EscalationLevel(), rec.ThreatScore())
			}
			if upstreamCalls.Load() != before {
				t.Fatalf("crossing request reached upstream: calls=%d before=%d", upstreamCalls.Load(), before)
			}
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) {
				t.Fatalf("%s threshold refusal: %d %v %s", wire, resp.StatusCode, resp.Header, body)
			}
			var reply rpcError
			if err := json.Unmarshal(body, &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Error.Code != -32001 || string(reply.ID) != wantID || len(reply.Error.Data) != 0 || !strings.Contains(reply.Error.Message, `category="session_deny"`) {
				t.Fatalf("threshold refusal: %s", body)
			}
			t.Logf("%s: status=%d reason=%q code=%d level=%d", wire, resp.StatusCode, resp.Header.Get(blockreason.HeaderReason), reply.Error.Code, rec.EscalationLevel())
		})
	}
}

func TestAdaptiveUniformRefusalMCPListenerConcurrentUnboundRecorders(t *testing.T) {
	injectionEntered, harmlessEntered := make(chan struct{}), make(chan struct{})
	releaseInjection, releaseHarmless := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, _ := io.ReadAll(r.Body)
		if bytes.Contains(request, []byte(`"id":1`)) {
			close(injectionEntered)
			select {
			case <-releaseInjection:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, upstreamStatusInjection)
			return
		}
		if bytes.Contains(request, []byte(`"id":2`)) {
			close(harmlessEntered)
			select {
			case <-releaseHarmless:
			case <-r.Context().Done():
				return
			}
		}
		// Withheld without a scored finding. It must not inherit request 1's level.
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = io.WriteString(w, "authentication required")
	}))
	t.Cleanup(upstream.Close)
	cfg := adaptiveCfgEnabled()
	cfg.EscalationThreshold = session.SignalPoints[session.SignalBlock]
	cfg.Levels.Elevated.BlockAll = boolPtr(true)
	store := &listenerDiagnosisStore{}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t), Store: store, AdaptiveCfg: cfg, listenerStateTokenRequired: boolPtr(true)})
	t.Cleanup(func() { close(releaseHarmless) })
	t.Cleanup(func() { close(releaseInjection) })
	type result struct {
		status int
		reason string
		body   []byte
		err    error
	}
	send := func(id int, out chan<- result) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/", strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list","params":{}}`, id)))
		if err != nil {
			out <- result{err: err}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			out <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		out <- result{status: resp.StatusCode, reason: resp.Header.Get(blockreason.HeaderReason), body: body, err: err}
	}
	injected, harmless := make(chan result, 1), make(chan result, 1)
	go send(1, injected)
	select {
	case <-injectionEntered:
	case <-t.Context().Done():
		t.Fatal("injection never reached upstream")
	}
	store.mu.Lock()
	if len(store.recs) != 1 {
		store.mu.Unlock()
		t.Fatal("request 1 did not get its own recorder")
	}
	var scored *listenerDiagnosisRecorder
	for _, rec := range store.recs {
		scored = rec
	}
	store.mu.Unlock()
	go send(2, harmless)
	select {
	case <-harmlessEntered:
	case <-t.Context().Done():
		t.Fatal("overlapping request never reached upstream")
	}
	store.mu.Lock()
	if len(store.recs) != 2 {
		store.mu.Unlock()
		t.Fatal("unbound requests did not get distinct recorders")
	}
	store.mu.Unlock()
	// Both requests are parked at upstream on distinct recorders. Record the
	// agent signal on request 1 only. Request 2 must not observe it, and the
	// withheld body must not add points of its own.
	scored.RecordSignal(session.SignalBlock, cfg.EscalationThreshold)
	if scored.EscalationLevel() != 1 {
		t.Fatalf("agent signal did not raise request 1: level=%d", scored.EscalationLevel())
	}
	scoreBeforeReply := scored.ThreatScore()
	releaseInjection <- struct{}{}
	first := <-injected
	if first.err != nil || first.status != http.StatusForbidden || first.reason != string(blockreason.EscalationLevel) || !bytes.Contains(first.body, []byte(`"code":-32001`)) {
		t.Fatalf("injection request: %+v body=%s", first, first.body)
	}
	if scored.ThreatScore() != scoreBeforeReply || scored.EscalationLevel() != 1 {
		t.Fatalf("withheld upstream reply changed score=%v level=%d, want score=%v level=1", scored.ThreatScore(), scored.EscalationLevel(), scoreBeforeReply)
	}
	store.mu.Lock()
	remaining := len(store.recs)
	for _, rec := range store.recs {
		if rec.EscalationLevel() != 0 {
			store.mu.Unlock()
			t.Fatal("in-flight harmless request inherited the other recorder's level")
		}
	}
	store.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("completed unbound recorder retained: %d remain", remaining)
	}
	releaseHarmless <- struct{}{}
	second := <-harmless
	if second.err != nil || second.status != http.StatusBadGateway || second.reason != "" || !bytes.Contains(second.body, []byte(`"code":-32003`)) {
		t.Fatalf("unscored request inherited lockdown: %+v body=%s", second, second.body)
	}
	go send(3, harmless)
	repeated := <-harmless
	if repeated.err != nil || repeated.status != http.StatusBadGateway || repeated.reason != "" {
		t.Fatalf("later unbound request inherited lockdown: %+v body=%s", repeated, repeated.body)
	}
	store.mu.Lock()
	remaining = len(store.recs)
	store.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("completed requests retained %d unbound recorders", remaining)
	}
	t.Logf("overlap: injection=%d/%s; unscored=%d/%q", first.status, first.reason, second.status, second.reason)
}
