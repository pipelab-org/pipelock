// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	mcpInitializeResource = "initialize"
	mcpToolsListResource  = "tools/list"
	mcpToolsCallResource  = "tools/call"
	runtimeTestPolicyHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestEmitDLPWarnWritesReceiptAndMetric(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(): %v", err)
	}

	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New(): %v", err)
	}
	t.Cleanup(func() {
		if closeErr := rec.Close(); closeErr != nil {
			t.Fatalf("rec.Close(): %v", closeErr)
		}
	})

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "cfg-hash",
		Actor:      "agent-1",
	})
	if emitter == nil {
		t.Fatal("receipt.NewEmitter() returned nil")
	}

	m := metrics.New()
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:     http.MethodGet,
		URL:        "https://example.com/api",
		ClientIP:   "10.0.0.1",
		RequestID:  "req-warn-1",
		Agent:      "agent-1",
		Transport:  "fetch",
		PolicyHash: runtimeTestPolicyHash,
	})

	emitDLPWarn(audit.NewNop(), m, emitter, ctx, "warn-url", "high")

	result, err := recorder.QuerySession(dir, "proxy", &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatalf("QuerySession(): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("receipt entry count = %d, want 1", len(result.Entries))
	}

	detailJSON, err := json.Marshal(result.Entries[0].Detail)
	if err != nil {
		t.Fatalf("jsonMarshal(detail): %v", err)
	}
	rcpt, err := receipt.Unmarshal(detailJSON)
	if err != nil {
		t.Fatalf("receipt.Unmarshal(): %v", err)
	}
	if rcpt.ActionRecord.Verdict != "warn" {
		t.Fatalf("receipt verdict = %q, want warn", rcpt.ActionRecord.Verdict)
	}
	if rcpt.ActionRecord.Layer != scanner.ScannerDLP {
		t.Fatalf("receipt layer = %q, want %q", rcpt.ActionRecord.Layer, scanner.ScannerDLP)
	}
	if rcpt.ActionRecord.Pattern != "warn-url" {
		t.Fatalf("receipt pattern = %q, want warn-url", rcpt.ActionRecord.Pattern)
	}
	if rcpt.ActionRecord.Severity != "high" {
		t.Fatalf("receipt severity = %q, want high", rcpt.ActionRecord.Severity)
	}
	if rcpt.ActionRecord.Target != "https://example.com" {
		t.Fatalf("receipt target = %q, want https://example.com", rcpt.ActionRecord.Target)
	}
	if rcpt.ActionRecord.PolicyHash != runtimeTestPolicyHash {
		t.Fatalf("receipt policy_hash = %q, want %q", rcpt.ActionRecord.PolicyHash, runtimeTestPolicyHash)
	}

	recorderBody := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(recorderBody, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(recorderBody.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(): %v", err)
	}
	if !strings.Contains(string(body), `pipelock_dlp_warn_matches_total{pattern="warn-url",transport="fetch"} 1`) {
		t.Fatalf("metrics missing warn counter:\n%s", string(body))
	}
}

func TestDLPWarnReceiptOptsUsesMCPMethod(t *testing.T) {
	opts := dlpWarnReceiptOpts(scanner.DLPWarnContext{
		Method:    "MCP",
		Resource:  mcpToolsCallResource,
		RequestID: "req-mcp-1",
		Agent:     "agent-mcp",
		Transport: "mcp_http",
	}, "warn-tool", "medium", "mcp_http")

	if opts.MCPMethod != mcpToolsCallResource {
		t.Fatalf("opts.MCPMethod = %q, want %s", opts.MCPMethod, mcpToolsCallResource)
	}
	if opts.Target != mcpToolsCallResource {
		t.Fatalf("opts.Target = %q, want %s", opts.Target, mcpToolsCallResource)
	}
}

func TestDLPWarnReceiptOptsTargetFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		wc         scanner.DLPWarnContext
		wantTarget string
		wantMethod string
	}{
		{
			name: "resource_takes_precedence",
			wc: scanner.DLPWarnContext{
				Resource: mcpToolsCallResource,
				URL:      "https://example.com",
				Target:   "explicit-target",
				Method:   "POST",
			},
			wantTarget: mcpToolsCallResource,
			wantMethod: "",
		},
		{
			name: "url_when_no_resource",
			wc: scanner.DLPWarnContext{
				URL:    "https://example.com/api",
				Target: "explicit-target",
				Method: http.MethodGet,
			},
			wantTarget: "https://example.com/api",
			wantMethod: http.MethodGet,
		},
		{
			name: "explicit_target_when_no_resource_or_url",
			wc: scanner.DLPWarnContext{
				Target: "some-target",
				Method: http.MethodPost,
			},
			wantTarget: "some-target",
			wantMethod: http.MethodPost,
		},
		{
			name:       "transport_fallback_when_nothing_set",
			wc:         scanner.DLPWarnContext{},
			wantTarget: "fetch",
			wantMethod: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := dlpWarnReceiptOpts(tt.wc, "test-pattern", "medium", "fetch")
			if opts.Target != tt.wantTarget {
				t.Errorf("Target = %q, want %q", opts.Target, tt.wantTarget)
			}
			if opts.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", opts.Method, tt.wantMethod)
			}
		})
	}
}

func TestEmitDLPWarnNilReceiptEmitter(t *testing.T) {
	m := metrics.New()
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodGet,
		URL:       "https://example.com/nil-emitter",
		ClientIP:  "10.0.0.2",
		RequestID: "req-nil-1",
		Agent:     "agent-nil",
		Transport: "fetch",
	})

	// nil receipt emitter must not panic; only metric + audit log emitted.
	emitDLPWarn(audit.NewNop(), m, nil, ctx, "warn-nil", "low")

	recorderBody := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(recorderBody, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(recorderBody.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(): %v", err)
	}
	if !strings.Contains(string(body), `pipelock_dlp_warn_matches_total{pattern="warn-nil",transport="fetch"} 1`) {
		t.Fatalf("metrics missing warn counter:\n%s", string(body))
	}
}

func TestEmitDLPWarnNilAuditLogger(t *testing.T) {
	// Passing nil metrics does not crash either (nil-safe counter method).
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodPost,
		URL:       "https://example.com/nil-logger",
		ClientIP:  "10.0.0.3",
		RequestID: "req-nil-2",
		Transport: "forward",
	})

	// The audit logger is a nop so nothing is written. The test verifies
	// that nil receiptEmitter + nop logger does not panic.
	emitDLPWarn(audit.NewNop(), nil, nil, ctx, "warn-nop", "low")
}

func TestEmitDLPWarnMissingTransport(t *testing.T) {
	m := metrics.New()
	// Context with no Transport field set; expect fallback to "unknown".
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodGet,
		URL:       "https://example.com/no-transport",
		ClientIP:  "10.0.0.4",
		RequestID: "req-no-transport",
	})

	emitDLPWarn(audit.NewNop(), m, nil, ctx, "warn-transport", "medium")

	recorderBody := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(recorderBody, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(recorderBody.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(): %v", err)
	}
	if !strings.Contains(string(body), `pipelock_dlp_warn_matches_total{pattern="warn-transport",transport="unknown"} 1`) {
		t.Fatalf("expected transport=unknown in metrics, got:\n%s", string(body))
	}
}

func TestNativeHeaderWarningsBoundSignedEvidence(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := acquireRunSession(rec)
	if err != nil {
		t.Fatal(err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: runtimeTestPolicyHash, Session: session})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	const pattern = "fixture advisory"
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/path", nil)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.SensitiveHeaders = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: pattern, Regex: "^FIXTURE-ADVISORY$", Severity: config.SeverityHigh, Action: config.ActionWarn,
	})
	for i := range 17 {
		header := fmt.Sprintf("X-Fixture-%02d", i)
		cfg.RequestBodyScanning.SensitiveHeaders = append(cfg.RequestBodyScanning.SensitiveHeaders, header)
		req.Header.Set(header, "FIXTURE-ADVISORY")
	}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var auditLog syncBuffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &auditLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	sc.SetDLPWarnHook(func(ctx context.Context, name, severity string) {
		emitDLPWarn(logger, nil, e, ctx, name, severity)
	})

	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	var cp atomic.Pointer[config.Config]
	var sp atomic.Pointer[scanner.Scanner]
	var ep atomic.Pointer[receipt.Emitter]
	cp.Store(cfg)
	sp.Store(sc)
	ep.Store(e)
	rp := proxy.NewReverseProxy(target, &cp, &sp, logger, metrics.New(), nil, nil, nil)
	rp.SetReceiptEmitter(&ep)
	response := httptest.NewRecorder()
	rp.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent || hits.Load() != 1 {
		t.Fatalf("upstream effect: status=%d hits=%d body=%s", response.Code, hits.Load(), response.Body)
	}
	if err := emitSessionCloseAndTranscriptRoot(e, session); err != nil {
		t.Fatal(err)
	}
	result, err := recorder.QuerySession(dir, session, &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	var individual, summary int
	for _, entry := range result.Entries {
		raw, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := receipt.Unmarshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		switch signed.ActionRecord.Pattern {
		case pattern:
			individual++
		case `additional warnings by pattern: {"fixture advisory":1}`:
			summary++
		default:
			continue
		}
		if err := receipt.VerifyWithKey(signed, e.SignerKeyHex()); err != nil {
			t.Fatalf("verify signed warning: %v", err)
		}
	}
	t.Logf("header warnings: wrote %d individual + %d overflow receipts, reserved %d", individual, summary, receipt.DLPWarningSlots)
	if individual != receipt.DLPWarningSlots-1 || summary != 1 {
		t.Fatalf("signed warnings = %d individual and %d summary, want 16 and 1", individual, summary)
	}
	if got := strings.Count(auditLog.String(), `"event":"dlp_warn"`); got != 17 {
		t.Fatalf("audit warnings = %d, want 17", got)
	}
	emitDLPWarn(logger, nil, e, req.Context(), pattern, config.SeverityHigh)
	if !strings.Contains(auditLog.String(), "emit DLP warn receipt") {
		t.Fatal("warning after seal did not report the receipt failure")
	}
}
