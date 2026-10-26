// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidence/completeness"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// openReceiptHarness starts a lifecycle-complete chain, as a running proxy
// does, so completeness analysis applies its intent/outcome pairing rules.
func openReceiptHarness(t *testing.T, opts *MCPProxyOpts, required bool) *mcpDecisionReceiptHarness {
	t.Helper()
	h := newMCPDecisionReceiptHarness(t)
	if err := h.v1.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	opts.ReceiptEmitter, opts.V2ReceiptEmitter, opts.PolicyHash, opts.RequireReceipts = h.v1, h.v2, mcpTestPolicyHash, required
	return h
}

func requireEvidenceNotBroken(t *testing.T, label string, h *mcpDecisionReceiptHarness) {
	t.Helper()
	if err := h.v1.EmitSessionClose("test"); err != nil {
		t.Fatal(err)
	}
	if err := h.rec.Close(); err != nil {
		t.Fatal(err)
	}
	receipts := readActionReceipts(t, h.dir)
	chain := receipt.VerifyChain(receipts, hex.EncodeToString(h.pub))
	if !chain.Valid {
		t.Fatalf("%s chain invalid: %s", label, chain.Error)
	}
	report := completeness.Analyze(receipts, chain)
	if report.Status == completeness.StatusBroken {
		for _, r := range receipts {
			a := r.ActionRecord
			t.Logf("%s seq=%d action=%s phase=%q verdict=%s layer=%s", label, a.ChainSeq, a.ActionID, a.DecisionPhase, a.Verdict, a.Layer)
		}
		t.Fatalf("%s evidence reported broken: %s", label, report.Error)
	}
}

func TestHTTPBridgeHeaderEvidenceCompleteness(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("forwarded/required=%t", required), func(t *testing.T) {
			var calls atomic.Int32
			up := bridgeHeaderUpstream(t, func(w http.ResponseWriter, _ *http.Request, f MCPFrame) {
				discoveryList(w, f, headerStateDefs(bridgeHeaderSchema, "Echo input"), "")
			}, func(w http.ResponseWriter, _ *http.Request, f MCPFrame) {
				calls.Add(1)
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}`, f.ID)
			})
			listenerOpts := paramContractOpts(t)
			listener := openReceiptHarness(t, &listenerOpts, required)
			listenerURL, _ := startListenerProxyWithOpts(t, up.URL, listenerOpts)
			bridgeOpts := bridgeHeaderOpts(t)
			bridge := openReceiptHarness(t, &bridgeOpts, required)
			headers := http.Header{"Proxy-Authorization": {"Bearer current-client-token"}}
			out, logs := runBridgeHeaderInput(t, listenerURL, bridgeHeaderCall(`{"region":"body"}`), headers, bridgeOpts)
			if calls.Load() != 1 || strings.Contains(out, `"error"`) {
				t.Fatalf("calls=%d out=%s logs=%s", calls.Load(), out, logs)
			}
			requireEvidenceNotBroken(t, "bridge", bridge)
			requireEvidenceNotBroken(t, "listener", listener)
		})
		t.Run(fmt.Sprintf("refused/required=%t", required), func(t *testing.T) {
			up := bridgeHeaderUpstream(t, func(w http.ResponseWriter, _ *http.Request, f MCPFrame) {
				discoveryList(w, f, `[]`, "")
			}, func(http.ResponseWriter, *http.Request, MCPFrame) { t.Error("refused call reached upstream") })
			opts := bridgeHeaderOpts(t)
			h := openReceiptHarness(t, &opts, required)
			out, logs := runBridgeHeaderInput(t, up.URL, bridgeHeaderCall(`{"region":"body"}`), nil, opts)
			if !strings.Contains(out, `"code":-32020`) {
				t.Fatalf("out=%s logs=%s", out, logs)
			}
			requireEvidenceNotBroken(t, "bridge", h)
		})
		t.Run(fmt.Sprintf("deferred refused/required=%t", required), func(t *testing.T) {
			up := bridgeHeaderUpstream(t, func(w http.ResponseWriter, _ *http.Request, f MCPFrame) {
				discoveryList(w, f, `[]`, "")
			}, func(http.ResponseWriter, *http.Request, MCPFrame) { t.Error("refused release reached upstream") })
			opts := bridgeHeaderOpts(t)
			h := openReceiptHarness(t, &opts, required)
			manager := newDeferKillManager(t)
			opts.DeferManager = manager
			policy := deferApprovalPolicy(config.DeferResolverProfile{})
			policy.Rules[0].ToolPattern = regexp.MustCompile(`^echo$`)
			policy.Rules[0].ResolutionPolicy.ResolverProfile = ""
			opts.PolicyCfg = policy
			inputR, inputW := io.Pipe()
			var out, logs syncBuffer
			done := make(chan error, 1)
			go func() { done <- RunHTTPProxy(t.Context(), inputR, &out, &logs, up.URL, nil, opts) }()
			if _, err := io.WriteString(inputW, bridgeHeaderCall(`{"region":"body"}`)+"\n"); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "held call")
			if err := manager.Resolve(manager.Snapshot()[0].DeferID, config.ActionAllow, "approval"); err != nil {
				t.Fatal(err)
			}
			if err := inputW.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(testwait.Deadline(10 * time.Second)):
				t.Fatal("bridge did not finish")
			}
			if !strings.Contains(out.String(), `"code":-32020`) {
				t.Fatalf("out=%s logs=%s", out.String(), logs.String())
			}
			requireEvidenceNotBroken(t, "bridge", h)
		})
	}
}
