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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/diaglog"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// Latency models a healthy pipe with a finite write delay, not synchronization.
type taintDeliverySink struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	latency time.Duration
}

func (s *taintDeliverySink) Write(p []byte) (int, error) {
	if s.latency > 0 {
		timer := time.NewTimer(s.latency)
		<-timer.C
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *taintDeliverySink) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.buf.String() }

// Default MCP CLI logging shares the audit stream and diagnostic writer.
func TestMCPTaintDiagnostics_RefusalPreservesBlockedAudit(t *testing.T) {
	for _, surface := range []string{"stdio", "http"} {
		for _, latency := range []time.Duration{0, time.Millisecond} {
			t.Run(surface+"/"+latency.String(), func(t *testing.T) {
				sink := &taintDeliverySink{latency: latency}
				w := diaglog.New(sink)
				al, err := audit.NewWithStream("json", "stdout", "", false, true, w)
				if err != nil {
					t.Fatal(err)
				}
				defer al.Close()
				cfg := config.Defaults()
				rec := &taintRecorder{}
				rec.ObserveRisk(session.ClassifyMCPResponseObservation(mcpTaintSourceKind, true, true))
				opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), InputCfg: newHTTPInputCfg(config.ActionBlock), Rec: rec, TaintCfg: &cfg.Taint, AuditLogger: al, Transport: transportMCPHTTP}
				msg := principalControlToolCall(1, "execute_command", `{"command":"id"}`)
				var denied *BlockedRequest
				if surface == "stdio" {
					opts.Transport = "mcp_stdio"
					blocked := make(chan BlockedRequest, 1)
					ForwardScannedInput(transport.NewStdioReader(bytes.NewReader(append(msg, '\n'))), transport.NewStdioWriter(io.Discard), w, config.ActionBlock, config.ActionBlock, blocked, nil, nil, opts)
					select {
					case d := <-blocked:
						denied = &d
					default:
						t.Fatal("no denial")
					}
				} else {
					denied = scanHTTPInputDecision(msg, w, "session", "session", opts).Blocked
				}
				if denied == nil || denied.ErrorCode != -32002 || denied.ErrorMessage != "pipelock: sensitive_action_after_hostile_external_exposure" {
					t.Fatalf("denial=%+v", denied)
				}
				waitTaintDiagnostic(t, w)
				out := sink.String()
				if got := strings.Count(out, `"event":"blocked"`); got != 1 {
					t.Fatalf("blocked audit events=%d, want exactly 1\n%s", got, out)
				}
				if !strings.Contains(out, `"scanner":"taint_policy"`) || !strings.Contains(out, `"event":"taint_decision"`) {
					t.Fatalf("taint audit evidence missing: %s", out)
				}
			})
		}
	}
}

func TestMCPTaintDiagnostics_NotificationPreservesAuditAndOperatorLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess fixture uses a POSIX command")
	}
	cfg := config.Defaults()
	sink := &taintDeliverySink{latency: time.Millisecond}
	w := diaglog.New(sink)
	al, err := audit.NewWithStream("json", "stdout", "", false, true, w)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), InputCfg: newHTTPInputCfg(config.ActionBlock), Store: &hostileDiagnosticStore{}, TaintCfg: &cfg.Taint, AuditLogger: al, Transport: "mcp_stdio", sessionExitForTest: liveSessionExitHooks()}
	msg := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_command","arguments":{"command":"id"}}}` + "\n"
	var client bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := RunProxy(ctx, strings.NewReader(msg), &client, w, []string{"/bin/cat"}, opts); err != nil {
		t.Fatal(err)
	}
	waitTaintDiagnostic(t, w)
	out := sink.String()
	if got := strings.Count(out, `"event":"blocked"`); got != 1 {
		t.Fatalf("notification blocked audit events=%d\n%s", got, out)
	}
	if !strings.Contains(out, "blocked notification (no response sent):") || !strings.Contains(out, "blocked by taint policy") {
		t.Fatalf("notification operator line missing: %s", out)
	}
	if client.Len() != 0 {
		t.Fatalf("notification generated client response: %s", client.String())
	}
}

type taintStartupGate struct {
	taintDeliverySink
	entered   chan struct{}
	release   chan struct{}
	childLine chan struct{}
	once      sync.Once
	childOnce sync.Once
}

func (s *taintStartupGate) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered); <-s.release })
	n, err := s.taintDeliverySink.Write(p)
	if strings.Contains(string(p), "child-stderr-line") {
		s.childOnce.Do(func() { close(s.childLine) })
	}
	return n, err
}

func TestMCPTaintDiagnostics_ChildStderrSurvivesSlowStartup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess fixture uses a POSIX shell")
	}
	sink := &taintStartupGate{entered: make(chan struct{}), release: make(chan struct{}), childLine: make(chan struct{})}
	w := diaglog.New(sink)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := filepath.Join(t.TempDir(), "started")
	hooks := liveSessionExitHooks()
	hooks.grace = 20 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		done <- RunProxy(ctx, strings.NewReader(""), io.Discard, w, []string{"/bin/sh", "-c", `echo child-stderr-line >&2; touch "$1"`, "sh", started}, MCPProxyOpts{sessionExitForTest: hooks})
	}()
	released := false
	defer func() {
		if !released {
			close(sink.release)
		}
		cancel()
		waitTaintDiagnostic(t, w)
	}()
	<-sink.entered
	// The child can only start after the bounded startup flush expires. Observe
	// that state instead of sleeping for a scheduler-dependent duration.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	waiting := true
	for waiting {
		select {
		case <-tick.C:
			if _, err := os.Stat(started); err == nil {
				waiting = false
			}
		case <-timer.C:
			t.Fatal("child did not start behind slow startup diagnostic")
		}
	}
	// Let the real subprocess and the bounded stderr drain finish first. This
	// proves the copier has attempted delivery before recovering the sink.
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not complete its bounded stderr drain")
	}
	close(sink.release)
	released = true
	select {
	case <-sink.childLine:
	case <-time.After(2 * time.Second):
		t.Fatal("wrapped server stderr was lost after temporary diagnostic slowness")
	}

	if got := strings.Count(sink.String(), "child-stderr-line"); got != 1 {
		t.Fatalf("stderr deliveries=%d", got)
	}
}

func TestMCPTaintDiagnostics_SkippedListenerReportRetainsWindow(t *testing.T) {
	cfg := config.Defaults()
	m := metrics.New()
	opts := MCPProxyOpts{TaintCfg: &cfg.Taint, Metrics: m}
	states := newMCPListenerClientStates(nil)
	sink := &taintStartupGate{entered: make(chan struct{}), release: make(chan struct{}), childLine: make(chan struct{})}
	w := diaglog.New(sink)
	// An ordinary write occupies the shared sink, so the optional report cannot
	// be admitted. It must leave the reporting window available for a retry.
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.WriteString(w, "ordinary\n") }()
	<-sink.entered
	released := false
	defer func() {
		if !released {
			close(sink.release)
		}
		waitTaintDiagnostic(t, w)
	}()
	if states.reportTaint(w, opts, nil, "listener_stateless") {
		t.Error("busy sink consumed listener reporting window")
	}
	assertSkippedTaintReports(t, m, 1)
	close(sink.release)
	released = true
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary write did not finish")
	}
	if !states.reportTaint(w, opts, nil, "listener_stateless") {
		t.Fatal("skipped report consumed the interval")
	}
	waitTaintDiagnostic(t, w)
	if !strings.Contains(sink.String(), "contexts since last report=2") {
		t.Fatalf("skipped context lost from aggregate: %s", sink.String())
	}
	if states.reportTaint(w, opts, nil, "listener_stateless") {
		t.Fatal("admitted report did not consume interval")
	}
	assertSkippedTaintReports(t, m, 1)
	if got := taintDiagnosticMetric(t, m, "listener_stateless", "inactive"); got != "3" {
		t.Fatal(got)
	}
}

func assertSkippedTaintReports(t *testing.T, m *metrics.Metrics, want int) {
	t.Helper()
	out := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(out, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	if !strings.Contains(out.Body.String(), fmt.Sprintf("pipelock_mcp_taint_reports_skipped_total %d\n", want)) {
		t.Fatalf("skipped optional report count missing; want %d", want)
	}
}

func TestMCPTaintDiagnostics_SkippedReportAccounting(t *testing.T) {
	for _, kind := range []string{"startup", "refusal", "nil", "empty", "healthy"} {
		t.Run(kind, func(t *testing.T) {
			cfg := config.Defaults()
			m := metrics.New()
			opts := MCPProxyOpts{TaintCfg: &cfg.Taint, Metrics: m}
			sink := &taintStartupGate{entered: make(chan struct{}), release: make(chan struct{}), childLine: make(chan struct{})}
			w := diaglog.New(sink)
			pending := w.Emit("busy\n")
			if pending == nil {
				t.Fatal("setup diagnostic not admitted")
			}
			<-sink.entered
			defer func() { close(sink.release); waitTaintDiagnostic(t, w) }()
			want := 0
			switch kind {
			case "startup":
				reportMCPTaintStartup(w, opts, nil, "stdio_subprocess")
				want = 1
			case "refusal":
				mcpTaintBlockMessage(taintDecision{}, w, opts)
				want = 1
			case "nil":
				if emitMCPTaintReport(nil, opts, "disabled") != nil {
					t.Fatal("nil sink admitted output")
				}
			case "empty":
				if emitMCPTaintReport(w, opts, "") != nil {
					t.Fatal("empty report admitted")
				}
			case "healthy":
				healthy := diaglog.New(io.Discard)
				if emitMCPTaintReport(healthy, opts, "optional") == nil {
					t.Fatal("healthy sink skipped output")
				}
				waitTaintDiagnostic(t, healthy)
			}
			assertSkippedTaintReports(t, m, want)
		})
	}
}
