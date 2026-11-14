// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// nonCoreStripeHalves is a Stripe key split so neither half matches alone.
// Stripe Key is not a core credential, so the configured action still decides.
func nonCoreStripeHalves() (string, string) {
	return "sk_te" + "st_4eC39HqLy", "jWDarjtT1z" + "dp7dc"
}

func coreAWSHalves() (string, string) {
	return "AKIA" + "QRST", "UVWXYZ" + "2345678901"
}

type mcpCoreFloorCase struct {
	name    string
	action  string
	audit   bool
	parts   []string
	blockAt int
	core    bool
}

func mcpCoreFloorCases() []mcpCoreFloorCase {
	awsPrefix, awsSuffix := coreAWSHalves()
	stripePrefix, stripeSuffix := nonCoreStripeHalves()
	return []mcpCoreFloorCase{
		{name: "core_warn_enforce", action: config.ActionWarn, parts: []string{awsPrefix, awsSuffix}, blockAt: 1, core: true},
		{name: "core_warn_audit", action: config.ActionWarn, audit: true, parts: []string{awsPrefix, awsSuffix}, blockAt: 1, core: true},
		{name: "noncore_warn", action: config.ActionWarn, parts: []string{stripePrefix, stripeSuffix}, blockAt: -1},
		{name: "noncore_block", action: config.ActionBlock, parts: []string{stripePrefix, stripeSuffix}, blockAt: 1},
		{name: "noncore_block_audit", action: config.ActionBlock, audit: true, parts: []string{stripePrefix, stripeSuffix}, blockAt: -1},
		{name: "mixed_window", action: config.ActionWarn, parts: []string{stripePrefix, stripeSuffix + awsPrefix, awsSuffix}, blockAt: 2, core: true},
	}
}

func mcpCoreFloorCEE(t *testing.T, action string) *CEEDeps {
	t.Helper()
	cee := NewCEEDeps(config.CrossRequestDetection{
		Enabled: true,
		Action:  action,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  testMCPWindowSecs / 60,
		},
	}, metrics.New())
	t.Cleanup(cee.Close)
	return cee
}

func TestCoreFloor_MCPStdioAndHTTP(t *testing.T) {
	for _, tc := range mcpCoreFloorCases() {
		t.Run(tc.name, func(t *testing.T) {
			sc := testMCPScanner()
			t.Cleanup(sc.Close)
			assertMCPStdioCoreFloor(t, sc, tc, tc.name == "core_warn_enforce")
			assertMCPHTTPCoreFloor(t, sc, tc)
		})
	}
}

func assertMCPStdioCoreFloor(t *testing.T, sc *scanner.Scanner, tc mcpCoreFloorCase, wantReceipt bool) {
	t.Helper()
	cee := mcpCoreFloorCEE(t, tc.action)
	var lines bytes.Buffer
	for i, part := range tc.parts {
		lines.Write(mcpChunkedCEERequest(i+1, part))
		lines.WriteByte('\n')
	}
	var server, logs bytes.Buffer
	blockedCh := make(chan BlockedRequest, len(tc.parts)+1)
	opts := MCPProxyOpts{Scanner: sc, CEE: cee, AuditMode: tc.audit, Transport: transportMCPStdio}
	var rec *recorder.Recorder
	var receiptDir string
	if wantReceipt {
		var emitter *receipt.Emitter
		emitter, rec, receiptDir, _ = newReceiptTestHarness(t)
		opts.ReceiptEmitter = emitter
	}
	ForwardScannedInput(
		transport.NewStdioReader(bytes.NewReader(lines.Bytes())),
		transport.NewStdioWriter(&server),
		&logs, config.ActionWarn, config.ActionBlock, blockedCh, nil, nil, opts,
	)
	var blocked int
	for range blockedCh {
		blocked++
	}
	wantBlocked := 0
	if tc.blockAt >= 0 {
		wantBlocked = len(tc.parts) - tc.blockAt
	}
	if blocked != wantBlocked {
		t.Fatalf("stdio blocked %d requests, want %d; log=%s forwarded=%q", blocked, wantBlocked, logs.String(), server.String())
	}
	if tc.blockAt >= 0 && strings.Contains(server.String(), tc.parts[tc.blockAt]) {
		t.Fatalf("stdio forwarded the refused part %q", tc.parts[tc.blockAt])
	}
	if tc.core && !strings.Contains(logs.String(), "core pattern cannot be downgraded") {
		t.Fatalf("stdio log = %s, want core floor refusal", logs.String())
	}
	if !wantReceipt {
		return
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	var found bool
	for _, rcpt := range readActionReceipts(t, receiptDir) {
		if rcpt.ActionRecord.Verdict == config.ActionBlock && rcpt.ActionRecord.Layer == "cross_request" && rcpt.ActionRecord.Pattern == "AWS Access ID" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("stdio block receipt missing core fragment pattern")
	}
}

func assertMCPHTTPCoreFloor(t *testing.T, sc *scanner.Scanner, tc mcpCoreFloorCase) {
	t.Helper()
	cee := mcpCoreFloorCEE(t, tc.action)
	opts := MCPProxyOpts{Scanner: sc, CEE: cee, AuditMode: tc.audit}
	var logs bytes.Buffer
	session := "core-floor-" + strings.ReplaceAll(t.Name(), "/", "-")
	for i, part := range tc.parts {
		blocked := scanHTTPInput(mcpChunkedCEERequest(i+1, part), &logs, session, session, opts)
		wantBlock := i == tc.blockAt
		if wantBlock {
			if blocked == nil {
				t.Fatalf("http part %d forwarded; log=%s", i, logs.String())
			}
			if blocked.ErrorMessage != "pipelock: "+ceeFragmentBlockClientReason {
				t.Fatalf("http part %d error = %q, want fragment block", i, blocked.ErrorMessage)
			}
			continue
		}
		if blocked != nil {
			t.Fatalf("http part %d refused: %+v", i, blocked)
		}
	}
	if tc.core && !strings.Contains(logs.String(), "core pattern cannot be downgraded") {
		t.Fatalf("http log = %s, want core floor refusal", logs.String())
	}
}
