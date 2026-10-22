// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// TestDeferredReleaseReceiptFailureReportsBlock pins that a released call whose
// required receipt cannot be written is reported, and journaled, as the block it
// is. The call is never sent, so an operator API answering "allow" for it, or a
// journal recording one, describes a release that did not happen.
//
// The healthy row is the positive control: the same approval with a working
// recorder is an allow everywhere.
func TestDeferredReleaseReceiptFailureReportsBlockAudit(t *testing.T) {
	tests := []struct {
		name         string
		breakRecords bool
		wantDecision string
		wantJournal  []string
		wantSent     bool
	}{
		{"recorder healthy", false, config.ActionAllow, []string{deferred.StateResolvedAllow + "/" + deferred.SourceOperator}, true},
		// With the recorder broken, neither the allow nor the corrective block
		// receipt can be confirmed, so no terminal entry is written: the hold
		// stays pending and restart recovery closes it with its own receipt.
		// The client is still refused.
		{"required receipt cannot be written", true, config.ActionBlock, nil, false},
	}

	t.Run("stdio", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ks := deferKillTestController()
				logger, events := newListenerEventLogger(t, func() {
					if got := ks.DeferredInFlight(); got != 0 {
						t.Errorf("denial sink retained %d upstream send claims", got)
					}
				})
				manager := newDeferKillManager(t)
				emitter, rec, _, _ := newReceiptTestHarnessWithObserver(t, nil)
				policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
				policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
				inputR, inputW := io.Pipe()
				var upstream, logBuf syncBuffer
				blocked := make(chan BlockedRequest, 4)
				done := make(chan struct{})
				go func() {
					defer close(done)
					ForwardScannedInput(transport.NewStdioReader(inputR), transport.NewStdioWriter(&upstream), &logBuf,
						config.ActionWarn, config.ActionBlock, blocked, nil, nil, MCPProxyOpts{
							AuditLogger: logger, Scanner: testInputScanner(t), PolicyCfg: policyCfg, DeferManager: manager,
							ReceiptEmitter: emitter, RequireReceipts: true,
							Transport: deferred.SurfaceMCPStdio, KillSwitch: ks,
						})
				}()
				if _, err := inputW.Write([]byte(deferKillTestCall)); err != nil {
					t.Fatalf("write input: %v", err)
				}
				testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "deferred stdio hold")
				held := manager.Snapshot()[0]
				if tt.breakRecords {
					_ = rec.Close()
				}
				got, err := manager.ResolveApprovalResult(held.DeferID, config.ActionAllow, deferred.SourceOperator)
				if err != nil {
					t.Fatalf("ResolveApprovalResult: %v", err)
				}
				if got != tt.wantDecision {
					t.Fatalf("reported decision = %q, want %q", got, tt.wantDecision)
				}
				if sent := strings.Contains(upstream.String(), "send_tool"); sent != tt.wantSent {
					t.Fatalf("call sent upstream = %v, want %v", sent, tt.wantSent)
				}
				if !tt.wantSent {
					select {
					case b := <-blocked:
						if b.ErrorCode != -32007 {
							t.Fatalf("client error code = %d, want -32007 receipt failure", b.ErrorCode)
						}
					default:
						t.Fatal("client was not told the call failed")
					}
				}
				assertTerminalJournalSequence(t, manager, held.DeferID, tt.wantJournal...)
				if err := inputW.Close(); err != nil {
					t.Fatalf("close input: %v", err)
				}
				<-done
				wantBlocks := 0
				if tt.breakRecords {
					wantBlocks = 1
				}
				if strings.Count(events.String(), `"event":"blocked"`) != wantBlocks || (wantBlocks == 1 && !strings.Contains(events.String(), `"scanner":"receipt_emission"`)) {
					t.Fatal(events.String())
				}
			})
		}
	})

	t.Run("http bridge", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ks := deferKillTestController()
				logger, events := newListenerEventLogger(t, func() {
					if got := ks.DeferredInFlight(); got != 0 {
						t.Errorf("denial sink retained %d upstream send claims", got)
					}
				})
				emitter, rec, _, _ := newReceiptTestHarnessWithObserver(t, nil)
				run := startHTTPDeferRun(t, ks, func(o *MCPProxyOpts) {
					o.AuditLogger = logger
					o.ReceiptEmitter = emitter
					o.RequireReceipts = true
				})
				held := run.manager.Snapshot()[0]
				if tt.breakRecords {
					_ = rec.Close()
				}
				got, err := run.manager.ResolveApprovalResult(held.DeferID, config.ActionAllow, deferred.SourceOperator)
				if err != nil {
					t.Fatalf("ResolveApprovalResult: %v", err)
				}
				if got != tt.wantDecision {
					t.Fatalf("reported decision = %q, want %q", got, tt.wantDecision)
				}
				wantCalls := int32(0)
				if tt.wantSent {
					wantCalls = 1
				}
				if calls := run.calls.Load(); calls != wantCalls {
					t.Fatalf("upstream requests = %d, want %d", calls, wantCalls)
				}
				if !tt.wantSent && !strings.Contains(run.stdout.String(), `"code":-32007`) {
					t.Fatalf("client was not told the receipt failed: %s", run.stdout.String())
				}
				assertTerminalJournalSequence(t, run.manager, held.DeferID, tt.wantJournal...)
				run.stop(t)
				wantBlocks := 0
				if tt.breakRecords {
					wantBlocks = 1
				}
				if strings.Count(events.String(), `"event":"blocked"`) != wantBlocks || (wantBlocks == 1 && !strings.Contains(events.String(), `"scanner":"receipt_emission"`)) {
					t.Fatal(events.String())
				}
			})
		}
	})
}
