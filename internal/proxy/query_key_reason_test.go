// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestQueryKeyBlockOmitsCanaryFromReasonReceiptAndBody(t *testing.T) {
	canary := strings.Join([]string{"Ab3kQ9mZ", "2xL7pW4n", "R8vT1cY6"}, "")
	target := "https://api.vendor.example/v1?page=1&" + canary + "=1"

	rph := newReceiptProxyHelper(t)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.Enforce = ptrBool(true)
	cfg.DLP.Patterns = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.FetchProxy.TimeoutSeconds = 5
	savedInternal := cfg.Internal
	cfg.ApplyDefaults()
	cfg.Internal = savedInternal

	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder:  rph.rec,
		Signer:    proxydecision.NewKeyedSigner(rph.priv),
		Principal: "local",
		Actor:     "pipelock",
	})
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(),
		WithRecorder(rph.rec),
		WithReceiptEmitter(rph.emitter),
		WithV2ReceiptEmitter(v2),
	)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	fetchReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+target, nil)
	fetchRec := httptest.NewRecorder()
	p.buildHandler(p.buildMux()).ServeHTTP(fetchRec, fetchReq)
	if fetchRec.Code != http.StatusForbidden {
		t.Fatalf("fetch status = %d, body = %s", fetchRec.Code, fetchRec.Body.String())
	}
	assertCanaryAbsent(t, "fetch body", fetchRec.Body.String(), canary)
	assertCanaryAbsent(t, "fetch headers", headerText(fetchRec.Header()), canary)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{
		Handler:           p.buildHandler(p.buildMux()),
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = ln.Close()
	})

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: api.vendor.example\r\n\r\n", target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read forward response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forward status = %d", resp.StatusCode)
	}
	forwardBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read forward body: %v", err)
	}
	assertCanaryAbsent(t, "forward body", string(forwardBody), canary)
	assertCanaryAbsent(t, "forward headers", headerText(resp.Header), canary)

	receipts := rph.findReceipts(t)
	var patterns int
	for _, rcpt := range receipts {
		if rcpt.ActionRecord.Pattern == "" {
			continue
		}
		patterns++
		assertCanaryAbsent(t, "v1 pattern", rcpt.ActionRecord.Pattern, canary)
	}
	if patterns == 0 {
		t.Fatal("no v1 receipt pattern")
	}

	var ruleIDs int
	for _, entry := range readRecorderEntries(t, rph.dir) {
		if entry.Type != "evidence_receipt" || entry.EventKind != string(contractreceipt.PayloadProxyDecision) {
			continue
		}
		var evidence contractreceipt.EvidenceReceipt
		if err := json.Unmarshal(entry.Detail, &evidence); err != nil {
			t.Fatalf("unmarshal v2 receipt: %v", err)
		}
		var payload contractreceipt.PayloadProxyDecisionStruct
		if err := json.Unmarshal(evidence.Payload, &payload); err != nil {
			t.Fatalf("unmarshal v2 payload: %v", err)
		}
		ruleIDs++
		assertCanaryAbsent(t, "v2 rule_id", payload.RuleID, canary)
		if !strings.Contains(payload.RuleID, "at position ") {
			t.Fatalf("v2 rule_id = %q", payload.RuleID)
		}
	}
	if ruleIDs == 0 {
		t.Fatal("no v2 rule_id")
	}
}

func assertCanaryAbsent(t *testing.T, surface, text, canary string) {
	t.Helper()
	if strings.Contains(text, canary) {
		t.Fatalf("%s contains the query key: %q", surface, text)
	}
}

func headerText(h http.Header) string {
	var b strings.Builder
	for name, values := range h {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(strings.Join(values, ","))
		b.WriteByte('\n')
	}
	return b.String()
}
