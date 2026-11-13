// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestForwardDenialCatalog(t *testing.T) {
	if forwardDenialCatalog[0].kind != forwardDenialUnclassified {
		t.Fatalf("catalog fallback = %q", forwardDenialCatalog[0].kind)
	}
	allowed := map[string]bool{
		sessionCapacityLayer:            true,
		scanner.AuditScannerUnavailable: true,
	}
	seen := map[forwardDenialKind]bool{}
	for _, spec := range forwardDenialCatalog {
		if spec.kind == "" || seen[spec.kind] {
			t.Errorf("duplicate or empty denial kind %q", spec.kind)
		}
		seen[spec.kind] = true
		if !allowed[spec.label] {
			t.Errorf("label %q is not the session-capacity layer or a published audit label", spec.label)
		}
		switch spec.metric {
		case forwardDenialMetricRequest, forwardDenialMetricTunnel:
		default:
			t.Errorf("%s metric %d", spec.kind, spec.metric)
		}
		if spec.write == forwardDenialWriteHTTP && (spec.status != http.StatusServiceUnavailable || spec.block == "") {
			t.Errorf("%s writes status %d reason %q", spec.kind, spec.status, spec.block)
		}
	}
	spec, known := forwardDenialSpecFor("missing")
	if known || spec.kind != forwardDenialUnclassified || spec.label != scanner.AuditScannerUnavailable || spec.reason == "" {
		t.Fatalf("unknown kind spec=%+v known=%v", spec, known)
	}
	for _, kind := range []forwardDenialKind{
		forwardDenialConnectSessionCapacity,
		forwardDenialConnectInterceptSessionCapacity,
		forwardDenialForwardSessionCapacity,
		forwardDenialForwardProfileSessionCapacity,
	} {
		got, ok := forwardDenialSpecFor(kind)
		if !ok || got.kind != kind || got.label != sessionCapacityLayer {
			t.Errorf("%s resolved %+v ok=%v", kind, got, ok)
		}
	}
}

func TestForwardDenialEmitterEvidence(t *testing.T) {
	reason := session.ErrCapacity.Error()
	profile := "profile-capacity-detail"
	cases := []struct {
		name          string
		kind          forwardDenialKind
		pattern       string
		transport     string
		method        string
		status        int
		body          string
		reasonHeader  string
		layer         string
		wantReason    string
		parentReceipt bool
		tunnels       float64
		requests      float64
		scannerHits   float64
		scannerLabel  string
		metrics       string
	}{
		{
			name:         "connect_session_capacity",
			kind:         forwardDenialConnectSessionCapacity,
			pattern:      "should-not-appear",
			transport:    TransportConnect,
			method:       http.MethodConnect,
			status:       http.StatusServiceUnavailable,
			body:         reason + "\n",
			reasonHeader: string(blockreason.DataBudget),
			layer:        sessionCapacityLayer,
			wantReason:   reason,
			tunnels:      1,
			metrics:      "pipelock_tunnels_total",
		},
		{
			name:          "connect_intercept_session_capacity",
			kind:          forwardDenialConnectInterceptSessionCapacity,
			pattern:       "should-not-appear",
			transport:     TransportConnect,
			method:        http.MethodConnect,
			status:        http.StatusOK,
			wantReason:    reason,
			parentReceipt: true,
			tunnels:       1,
			metrics:       "pipelock_tunnels_total",
		},
		{
			name:         "forward_session_capacity",
			kind:         forwardDenialForwardSessionCapacity,
			pattern:      "should-not-appear",
			transport:    TransportForward,
			method:       http.MethodGet,
			status:       http.StatusServiceUnavailable,
			body:         reason + "\n",
			reasonHeader: string(blockreason.DataBudget),
			layer:        sessionCapacityLayer,
			wantReason:   reason,
			requests:     1,
			scannerHits:  1,
			scannerLabel: sessionCapacityLayer,
			metrics:      "pipelock_requests_total",
		},
		{
			name:         "forward_profile_session_capacity",
			kind:         forwardDenialForwardProfileSessionCapacity,
			pattern:      profile,
			transport:    TransportForward,
			method:       http.MethodGet,
			status:       http.StatusOK,
			wantReason:   profile,
			requests:     1,
			scannerHits:  1,
			scannerLabel: sessionCapacityLayer,
			metrics:      "pipelock_requests_total",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, actionID, measured := driveForwardDenial(t, tc.kind, tc.pattern)
			if got.status != tc.status || got.body != tc.body {
				t.Fatalf("status=%d body=%q", got.status, got.body)
			}
			if tc.reasonHeader == "" {
				if got.headers.Get(blockreason.HeaderReason) != "" || got.headers.Get(blockreason.HeaderLayer) != "" {
					t.Fatalf("response wrote block headers: %v", got.headers)
				}
			} else if got.headers.Get(blockreason.HeaderReason) != tc.reasonHeader || got.headers.Get(blockreason.HeaderLayer) != tc.layer {
				t.Fatalf("headers=%v", got.headers)
			}
			if len(got.blocked) != 1 {
				t.Fatalf("blocked=%v", got.blocked)
			}
			blocked := got.blocked[0]
			if blocked["scanner"] != sessionCapacityLayer || blocked["reason"] != tc.wantReason {
				t.Fatalf("blocked=%v", blocked)
			}
			if _, ok := blocked["block_class"]; ok {
				t.Fatalf("blocked event carries block_class: %v", blocked)
			}
			if strings.Contains(got.body, "should-not-appear") || blocked["reason"] == "should-not-appear" {
				t.Fatalf("caller pattern leaked into %s", tc.name)
			}
			if got.counters["pipelock_tunnels_total{result=blocked,agent=_default}"] != tc.tunnels ||
				got.counters["pipelock_requests_total{result=blocked,agent=_default}"] != tc.requests ||
				scannerHits(t, measured, tc.scannerLabel) != tc.scannerHits ||
				got.blockMetrics != tc.metrics || got.events != "blocked" {
				t.Fatalf("counters=%v hits=%v metrics=%s events=%s", got.counters, scannerHits(t, measured, tc.scannerLabel), got.blockMetrics, got.events)
			}
			blocks := blockReceipts(got.receipts)
			if len(blocks) != 1 || len(got.receipts) != 1 {
				t.Fatalf("receipts=%d blocks=%d", len(got.receipts), len(blocks))
			}
			rec := blocks[0].ActionRecord
			if rec.Layer != sessionCapacityLayer || rec.Pattern != tc.wantReason || rec.Verdict != config.ActionBlock ||
				rec.Transport != tc.transport || rec.Method != tc.method || rec.Actor != agentAnonymous ||
				rec.ActionType != receipt.ActionRead || rec.Target != "https://api.vendor.example" || rec.PolicyHash == "" || rec.Redaction != nil {
				t.Fatalf("receipt=%+v", rec)
			}
			if tc.parentReceipt {
				if rec.ParentActionID != actionID || rec.ActionID == actionID || rec.ActionID == "" {
					t.Fatalf("parent=%q action=%q request=%q", rec.ParentActionID, rec.ActionID, actionID)
				}
			} else if rec.ParentActionID != "" || rec.ActionID != actionID {
				t.Fatalf("parent=%q action=%q request=%q", rec.ParentActionID, rec.ActionID, actionID)
			}
			if got.headers.Get(blockreason.HeaderRecordedReceipt) != rec.ActionID {
				t.Fatalf("recorded header=%q action=%q", got.headers.Get(blockreason.HeaderRecordedReceipt), rec.ActionID)
			}
		})
	}
}

func TestForwardDenialUnknownKindRefuses(t *testing.T) {
	const caller = "caller-pattern-must-not-leak"
	got, actionID, measured := driveForwardDenial(t, "missing", caller)
	fallback, known := forwardDenialSpecFor("missing")
	if known {
		t.Fatal("unknown kind accepted")
	}
	reason := fallback.reason
	if got.status != http.StatusServiceUnavailable || got.body != reason+"\n" {
		t.Fatalf("status=%d body=%q", got.status, got.body)
	}
	wantHeaders := map[string]string{
		blockreason.HeaderReason:   string(blockreason.PatternUnavailable),
		blockreason.HeaderLayer:    scanner.AuditScannerUnavailable,
		blockreason.HeaderSeverity: string(blockreason.SeverityWarn),
		blockreason.HeaderRetry:    string(blockreason.RetryTransient),
		blockreason.HeaderVersion:  blockreason.SchemaVersion,
		"Content-Type":             "text/plain; charset=utf-8",
		"X-Content-Type-Options":   "nosniff",
	}
	for key, value := range wantHeaders {
		if got.headers.Get(key) != value {
			t.Fatalf("%s=%q want %q", key, got.headers.Get(key), value)
		}
	}
	if got.headers.Get(blockreason.HeaderReceipt) != "" {
		t.Fatalf("receipt header=%q", got.headers.Get(blockreason.HeaderReceipt))
	}
	if len(got.blocked) != 1 {
		t.Fatalf("blocked=%v events=%s", got.blocked, got.events)
	}
	blocked := got.blocked[0]
	if blocked["scanner"] != scanner.AuditScannerUnavailable || blocked["reason"] != reason || blocked["event"] != "blocked" {
		t.Fatalf("blocked=%v", blocked)
	}
	if _, ok := blocked["block_class"]; ok {
		t.Fatalf("blocked event carries block_class: %v", blocked)
	}
	if strings.Contains(got.body, caller) || strings.Contains(blocked["reason"].(string), caller) {
		t.Fatal("caller pattern leaked")
	}
	if got.counters["pipelock_requests_total{result=blocked,agent=_default}"] != 1 ||
		got.counters["pipelock_tunnels_total{result=blocked,agent=_default}"] != 0 ||
		scannerHits(t, measured, scanner.AuditScannerUnavailable) != 1 ||
		got.blockMetrics != "pipelock_requests_total" || got.events != "blocked" {
		t.Fatalf("counters=%v metrics=%s events=%s", got.counters, got.blockMetrics, got.events)
	}
	blocks := blockReceipts(got.receipts)
	if len(blocks) != 1 || len(got.receipts) != 1 {
		t.Fatalf("receipts=%d", len(got.receipts))
	}
	rec := blocks[0].ActionRecord
	if rec.Layer != scanner.AuditScannerUnavailable || rec.Pattern != reason || rec.Verdict != config.ActionBlock ||
		rec.ParentActionID != "" || rec.ActionID != actionID || rec.Actor != agentAnonymous ||
		rec.ActionType != receipt.ActionRead || strings.Contains(rec.Pattern, caller) {
		t.Fatalf("receipt=%+v", rec)
	}
	if got.headers.Get(blockreason.HeaderRecordedReceipt) != rec.ActionID || got.headers.Get(blockreason.HeaderRequestID) != rec.RequestID {
		t.Fatalf("headers=%v", got.headers)
	}
}

func driveForwardDenial(t *testing.T, kind forwardDenialKind, pattern string) (capacityEvidence, string, *metrics.Metrics) {
	t.Helper()
	cfg := config.Defaults()
	proxy := &Proxy{metrics: metrics.New()}
	sink := attachCapacityEvidence(t, proxy)
	requestID := receiptcontent.NewRequestID()
	if requestID == "" {
		t.Fatal("request id")
	}
	ctx, err := audit.NewHTTPLogContext(http.MethodGet, "https://api.vendor.example/submit", "192.0.2.77", requestID, agentAnonymous)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	actionID := receipt.NewActionID()
	selected := proxy.admitReceiptShard()
	proxy.emitForwardDenial(forwardDenial{
		Kind:        kind,
		Pattern:     pattern,
		Context:     ctx,
		Writer:      recorder,
		RequestID:   requestID,
		Agent:       agentAnonymous,
		MetricAgent: edition.ProfileDefault,
		Hostname:    "api.vendor.example",
		Started:     time.Now(),
		ActionID:    actionID,
		Method:      methodForKind(kind),
		Target:      "https://api.vendor.example/submit",
		Transport:   transportForKind(kind),
		Emit: func(opts receipt.EmitOpts) {
			opts = withReceiptShard(opts, selected)
			opts = withReceiptConfig(opts, cfg)
			if e := proxy.receiptEmitterPtr.Load(); e != nil && proxy.emitReceiptWithEmitter(opts, e) == nil {
				if opts.Verdict == config.ActionBlock {
					blockreason.SetRecordedReceipt(recorder.Header(), opts.ActionID)
				}
			}
		},
	})
	return sink.evidence(t, proxy, recorder.Code, recorder.Header(), recorder.Body.String(), 0), actionID, proxy.metrics
}

func methodForKind(kind forwardDenialKind) string {
	switch kind {
	case forwardDenialConnectSessionCapacity, forwardDenialConnectInterceptSessionCapacity:
		return http.MethodConnect
	default:
		return http.MethodGet
	}
}

func transportForKind(kind forwardDenialKind) string {
	switch kind {
	case forwardDenialConnectSessionCapacity, forwardDenialConnectInterceptSessionCapacity:
		return TransportConnect
	default:
		return TransportForward
	}
}

func scannerHits(t *testing.T, m *metrics.Metrics, label string) float64 {
	t.Helper()
	if label == "" {
		return 0
	}
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, family := range families {
		if family.GetName() != "pipelock_scanner_hits_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricHasLabel(metric, "scanner", label) && metricHasLabel(metric, "agent", edition.ProfileDefault) {
				total += metricValue(metric)
			}
		}
	}
	return total
}
