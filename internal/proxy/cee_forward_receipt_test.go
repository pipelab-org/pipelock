// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A forward request refused by cross-request fragment reassembly signs one
// block receipt, as every other transport does for the same decision.
func TestForwardCEEFragmentDenialEmitsReceipt(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	cfg.RequestBodyScanning.Enabled = false
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = config.ActionBlock
	cfg.CrossRequestDetection.EntropyBudget.Enabled = false
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	cfg.ApplyDefaults()
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	var records bytes.Buffer
	log, err := audit.NewWithStream("json", "stdout", "", true, true, &records)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(log.Close)
	p, err := New(cfg, log, sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if p.fragmentBufferPtr.Load() == nil {
		t.Fatal("CEE fragment buffer not initialized")
	}
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
	hits := 0
	p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
		hits++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("accepted")), Request: r}, nil
	})}

	half := len(testCEEFakeAWSKey) / 2
	parts := []string{"key part " + testCEEFakeAWSKey[:half], testCEEFakeAWSKey[half:]}
	var blocked *httptest.ResponseRecorder
	for i, part := range parts {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/upload", strings.NewReader(part))
		req.Header.Set("Content-Type", "text/plain")
		req.RemoteAddr = "192.0.2.1:12345"
		w := httptest.NewRecorder()
		p.handleForwardHTTP(w, req)
		want := http.StatusOK
		if i == len(parts)-1 {
			want = http.StatusForbidden
			blocked = w
		}
		if w.Code != want {
			t.Fatalf("fragment=%d status=%d want=%d body=%s", i, w.Code, want, w.Body.String())
		}
	}
	if hits != 1 {
		t.Fatalf("upstream hits=%d want=1", hits)
	}
	headerID := blocked.Header().Get(blockreason.HeaderRecordedReceipt)
	if headerID == "" {
		t.Fatalf("blocked response names no recorded receipt")
	}

	receipts := rph.findReceipts(t)
	denials := 0
	for _, r := range receipts {
		if err := receipt.VerifyWithKey(r, rph.pubHex); err != nil {
			t.Fatal(err)
		}
		if r.ActionRecord.Layer != "cross_request" || r.ActionRecord.Verdict != config.ActionBlock {
			continue
		}
		denials++
		if r.ActionRecord.ActionID != headerID {
			t.Fatalf("receipt action %q, header names %q", r.ActionRecord.ActionID, headerID)
		}
		if r.ActionRecord.PolicyHash != cfg.CanonicalPolicyHash() {
			t.Fatal("receipt policy hash differs from deciding config")
		}
		if r.ActionRecord.Transport != TransportForward {
			t.Fatalf("transport=%q", r.ActionRecord.Transport)
		}
	}
	if denials != 1 {
		t.Fatalf("forward CEE denial receipts=%d want=1; total receipts=%d", denials, len(receipts))
	}
	requireSignedRecordedReceipt(t, rph, receipts, headerID)
}
