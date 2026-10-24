// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/diaglog"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func taintDiagnosticMetric(t *testing.T, m *metrics.Metrics, binding, status string) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	prefix := fmt.Sprintf(`pipelock_mcp_taint_contexts_total{binding=%q,status=%q} `, binding, status)
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return "0"
}

func TestMCPTaintDiagnostics_ListenerLogsThrottledMetricsComplete(t *testing.T) {
	var log *syncBuffer
	t.Run("requests", func(t *testing.T) {
		upstream, _ := principalStateUpstream(t)
		cfg := config.Defaults()
		m := metrics.New()
		opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Metrics: m}
		base, buf := startListenerProxyWithOpts(t, upstream.URL, opts)
		log = buf
		for i := range 5 {
			status, _ := mustPrincipalControlRPC(t, base, "", principalControlToolCall(i+1, "read_file", `{}`))
			if status != http.StatusOK {
				t.Fatalf("status=%d", status)
			}
		}
		if got := taintDiagnosticMetric(t, m, "listener_stateless", "inactive"); got != "5" {
			t.Errorf("metric=%s want 5", got)
		}
	})
	if got := strings.Count(log.String(), "pipelock: MCP taint binding="); got != 1 {
		t.Errorf("taint log count=%d want 1", got)
	}
	if got := strings.Count(log.String(), "origin="); got != 1 {
		t.Errorf("origin log count=%d want 1", got)
	}
}

type taintAdmissionFailureStore struct{ listenerDiagnosisStore }

func (s *taintAdmissionFailureStore) GetOrCreate(key string) session.Recorder {
	if strings.HasPrefix(key, "mcp-http-listener-principal:") {
		return nil
	}
	return s.listenerDiagnosisStore.GetOrCreate(key)
}

func TestMCPTaintDiagnostics_ListenerAdmissionFailureNotActive(t *testing.T) {
	var log *syncBuffer
	t.Run("request", func(t *testing.T) {
		upstream, calls := principalStateUpstream(t)
		cfg := config.Defaults()
		m := metrics.New()
		opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Metrics: m, Store: &taintAdmissionFailureStore{}}
		opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
			return ListenerPrincipal{Provider: "test", Subject: "verified"}, nil
		}
		base, buf := startListenerProxyWithOpts(t, upstream.URL, opts)
		log = buf
		status, body := mustPrincipalControlRPC(t, base, "", principalControlToolCall(1, "read_file", `{}`))
		if status != http.StatusServiceUnavailable || !strings.Contains(body, "state capacity exhausted") || calls.Load() != 0 {
			t.Fatalf("refusal=%d %s calls=%d", status, body, calls.Load())
		}
		if got := taintDiagnosticMetric(t, m, "listener_principal", "active"); got != "0" {
			t.Errorf("refused principal active metric=%s", got)
		}
		if got := taintDiagnosticMetric(t, m, "listener_principal", "inactive"); got != "1" {
			t.Errorf("inactive metric=%s", got)
		}
	})
	if !strings.Contains(log.String(), "binding=listener_principal recorder_risk_state=false cross_request_recording=inactive") {
		t.Errorf("refused principal claimed recording: %s", log.String())
	}
}

func TestMCPTaintDiagnostics_ListenerJunkTokenDoesNotChooseBinding(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			var log *syncBuffer
			t.Run("request", func(t *testing.T) {
				upstream, _ := principalStateUpstream(t)
				cfg := config.Defaults()
				m := metrics.New()
				opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Metrics: m, Store: &listenerDiagnosisStore{}}
				base, buf, logW := startListenerProxyWithDiagnosticLog(t, upstream.URL, opts)
				defer waitTaintDiagnostic(t, logW)
				log = buf
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
				req.Header.Set("Mcp-Protocol-Version", "2025-03-26")
				req.Header.Set("Mcp-Method", "tools/call")
				req.Header.Set("Mcp-Name", "read_file")
				junk, err := newMCPListenerSessionToken()
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set(listenerSessionTokenHeader, junk)
				if legacy {
					req.Header.Set("Mcp-Session-Id", "legacy-session")
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status %d", resp.StatusCode)
				}
				if got := taintDiagnosticMetric(t, m, "listener_token", "active"); got != "0" {
					t.Errorf("junk token counted active: %s", got)
				}
			})
			binding := "listener_stateless"
			if legacy {
				binding = "listener_legacy"
			}
			if !strings.Contains(log.String(), "binding="+binding+" ") {
				t.Errorf("junk token chose label: %s", log.String())
			}
		})
	}
}

func TestMCPTaintDiagnostics_ListenerCapacityNotActive(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	cfg := config.Defaults()
	m := metrics.New()
	subject := 0
	opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Metrics: m, Store: &listenerDiagnosisStore{}}
	// The verifier supplies distinct identities. DELETE keeps principal history,
	// exercising real registry admission without scanning thousands of tool bodies.
	opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
		subject++
		return ListenerPrincipal{Provider: "test", Subject: fmt.Sprint(subject)}, nil
	}
	base, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	request := func() int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, base+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for i := range maxMCPListenerClients {
		if status := request(); status != http.StatusNoContent {
			t.Fatalf("admission %d status=%d", i, status)
		}
	}
	if status := request(); status != http.StatusServiceUnavailable || calls.Load() != maxMCPListenerClients {
		t.Fatalf("capacity status=%d calls=%d", status, calls.Load())
	}
	if got := taintDiagnosticMetric(t, m, "listener_principal", "active"); got != fmt.Sprint(maxMCPListenerClients) {
		t.Errorf("capacity refusal counted active: %s", got)
	}
	if got := taintDiagnosticMetric(t, m, "listener_principal", "inactive"); got != "1" {
		t.Errorf("capacity refusal inactive=%s", got)
	}
}

func TestMCPTaintDiagnostics_ListenerReportAggregation(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil report writer panicked: %v", r)
		}
	}()
	now := time.Now()
	states := newMCPListenerClientStates(nil)
	// Zero selects the existing listener reporting interval.
	states.taintReporter = newMCPListenerDegradationReporter(0, func() time.Time { return now })
	cfg := config.Defaults()
	m := metrics.New()
	opts := MCPProxyOpts{TaintCfg: &cfg.Taint, Metrics: m}
	var out bytes.Buffer
	logW := diaglog.New(&out)
	if !states.reportTaint(logW, opts, nil, "listener_stateless") {
		t.Fatal("first context not emitted")
	}
	waitTaintDiagnostic(t, logW)
	for range 2 {
		if states.reportTaint(logW, opts, nil, "listener_stateless") {
			t.Fatal("context not throttled")
		}
	}
	now = now.Add(listenerDegradationReportInterval)
	if !states.reportTaint(logW, opts, nil, "listener_stateless") {
		t.Fatal("interval report not emitted")
	}
	waitTaintDiagnostic(t, logW)
	if !strings.Contains(out.String(), "contexts since last report=3") || strings.Count(out.String(), "MCP taint binding=") != 2 {
		t.Fatalf("wrong aggregated reports: %s", out.String())
	}
	if got := taintDiagnosticMetric(t, m, "listener_stateless", "inactive"); got != "4" {
		t.Fatalf("throttled contexts dropped: %s", got)
	}
	// No configured log sink still counts contexts, including a later aggregate.
	if states.reportTaint(nil, opts, nil, "listener_stateless") {
		t.Fatal("nil sink bypassed throttle")
	}
	now = now.Add(listenerDegradationReportInterval)
	states.reportTaint(nil, opts, nil, "listener_stateless")
	if got := taintDiagnosticMetric(t, m, "listener_stateless", "inactive"); got != "6" {
		t.Fatal("nil writer dropped metrics")
	}
}

type hostileDiagnosticStore struct{ listenerDiagnosisStore }

func (s *hostileDiagnosticStore) GetOrCreate(key string) session.Recorder {
	rec := s.listenerDiagnosisStore.GetOrCreate(key)
	rec.(session.RiskState).ObserveRisk(session.ClassifyMCPResponseObservation(mcpTaintSourceKind, true, true))
	return rec
}

func TestMCPTaintDiagnostics_ListenerRecoveryThrottled(t *testing.T) {
	var log *syncBuffer
	t.Run("requests", func(t *testing.T) {
		upstream, calls := principalStateUpstream(t)
		cfg := config.Defaults()
		m := metrics.New()
		opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), InputCfg: newHTTPInputCfg(config.ActionBlock), TaintCfg: &cfg.Taint, Metrics: m, Store: &hostileDiagnosticStore{}}
		opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
			return ListenerPrincipal{Provider: "test", Subject: "verified"}, nil
		}
		base, buf := startListenerProxyWithOpts(t, upstream.URL, opts)
		log = buf
		for i := range 5 {
			_, body := mustPrincipalControlRPC(t, base, "", principalControlToolCall(i+1, "execute_command", `{"command":"id"}`))
			if got := principalControlRPCError(t, body); got != "pipelock: sensitive_action_after_hostile_external_exposure" {
				t.Fatalf("client error=%s", got)
			}
		}
		if calls.Load() != 0 {
			t.Fatal("hostile call forwarded")
		}
		if got := taintDiagnosticMetric(t, m, "listener_principal", "active"); got != "5" {
			t.Errorf("recorded contexts=%s", got)
		}
	})
	if got := strings.Count(log.String(), "; recovery: "); got != 1 {
		t.Errorf("recovery guidance log count=%d want 1", got)
	}
}

func TestMCPTaintDiagnostics_NilRecoveryWriter(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil recovery writer panicked: %v", r)
		}
	}()
	if got := mcpTaintBlockMessage(taintDecision{}, nil, MCPProxyOpts{}); got != "pipelock: " {
		t.Errorf("client reason=%q", got)
	}
}
