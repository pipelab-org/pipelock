// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// A held call whose policy allows release on a confirmed tool inventory must
// not be released by the structural collection the bridge runs when the
// operator configured no tool scanning: nothing inspected those definitions.
func TestHTTPBridgeContractsOnlyInventoryKeepsHolds(t *testing.T) {
	for _, toolScanning := range []bool{false, true} {
		t.Run(fmt.Sprintf("toolScanning=%t", toolScanning), func(t *testing.T) {
			var calls atomic.Int32
			up := bridgeHeaderUpstream(t, func(w http.ResponseWriter, _ *http.Request, f MCPFrame) {
				discoveryList(w, f, headerStateDefs(bridgeHeaderSchema, "Echo input"), "")
			}, func(w http.ResponseWriter, _ *http.Request, f MCPFrame) {
				calls.Add(1)
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}`, f.ID)
			})
			opts := bridgeHeaderOpts(t)
			if !toolScanning {
				opts.ToolCfg = nil
			}
			h := newMCPDecisionReceiptHarness(t)
			opts.ReceiptEmitter, opts.V2ReceiptEmitter, opts.PolicyHash = h.v1, h.v2, mcpTestPolicyHash
			manager := newDeferKillManager(t)
			opts.DeferManager = manager
			policy := deferApprovalPolicy(config.DeferResolverProfile{})
			policy.Rules[0].ToolPattern = regexp.MustCompile(`^echo$`)
			policy.Rules[0].ResolutionPolicy.ResolverProfile = ""
			policy.Rules[0].ResolutionPolicy.AllowOn = config.DeferAllowOn{ToolInventoryBaseline: true}
			opts.PolicyCfg = policy
			inputR, inputW := io.Pipe()
			var out, logs syncBuffer
			done := make(chan error, 1)
			go func() { done <- RunHTTPProxy(t.Context(), inputR, &out, &logs, up.URL, nil, opts) }()
			write := func(line string) {
				if _, err := io.WriteString(inputW, line+"\n"); err != nil {
					t.Fatal(err)
				}
			}
			write(currentWireBody(0, "tools/list", ""))
			write(bridgeHeaderCall(`{"region":"body"}`))
			testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "held call")
			write(currentWireBody(3, "tools/list", ""))
			// The loop finishes one message, including its inventory
			// resolution, before reading the next; id 4 fences id 3.
			write(currentWireBody(4, "tools/list", ""))
			testwait.For(t, 5*time.Second, func() bool { return strings.Contains(out.String(), `"id":4`) }, "fenced inventory")
			pending, released := len(manager.Snapshot()), calls.Load()
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
			if toolScanning && (pending != 0 || released != 1) {
				t.Fatalf("scanned inventory did not release: pending=%d calls=%d logs=%s", pending, released, logs.String())
			}
			if !toolScanning && (pending != 1 || released != 0) {
				t.Fatalf("structural inventory released a hold: pending=%d calls=%d logs=%s", pending, released, logs.String())
			}
		})
	}
}
