// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// The audit wiring records external checker outcomes and a failed
// known-answer self-test, without content.
func TestWirePromptInjectionAuditRecordsCheckerOutcomes(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorDown)
	allow := true
	r := checkertest.MockRevision
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{
		Checkers: map[string]config.InjectionCheckerConfig{"local": {
			Type: config.InjectionCheckerTypeProtocol, Endpoint: m.URL, AllowLoopbackHTTP: &allow,
			Revision:  &config.InjectionCheckerRevision{Checker: r.Checker, Model: r.Model, Adapter: r.Adapter},
			TimeoutMS: 2000, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12,
		}},
		Surfaces: map[string]config.InjectionSurfaceConfig{config.InjectionSurfaceMCPToolResult: {Checker: "local", Mode: config.InjectionModeBlock}},
	}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)

	wirePromptInjectionAudit(sc, logger)
	read := func() string {
		data, _ := os.ReadFile(filepath.Clean(path))
		return string(data)
	}
	testwait.For(t, testwait.Deadline(10*time.Second), func() bool {
		return strings.Contains(read(), "self_test_failed")
	}, "self-test failure was not audited")

	sc.ReportInjectionChecker(context.Background(), scanner.InjectionCheckerEvent{
		Checker: "local", Surface: config.InjectionSurfaceMCPToolResult, Mode: config.InjectionModeBlock,
		State: "not_assessed", Reason: "unavailable",
	})
	testwait.For(t, testwait.Deadline(10*time.Second), func() bool {
		return strings.Contains(read(), `"surface":"mcp_tool_result"`)
	}, "checker outcome was not audited")
	if strings.Contains(read(), checkertest.SuspiciousMarker) {
		t.Fatal("audit log carries probe content")
	}
}

// Assessed content a checker echoes as its reason ID never reaches the audit
// log, from either the deciding or the watch event path.
func TestCheckerReasonIDNeverReachesAuditLog(t *testing.T) {
	const echoed = "secret_token_123"
	m := checkertest.NewMockServer(t, checkertest.BehaviorEchoReason)
	allow := true
	r := checkertest.MockRevision
	def := config.InjectionCheckerConfig{
		Type: config.InjectionCheckerTypeProtocol, Endpoint: m.URL, AllowLoopbackHTTP: &allow,
		Revision:  &config.InjectionCheckerRevision{Checker: r.Checker, Model: r.Model, Adapter: r.Adapter},
		TimeoutMS: 2000, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12,
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{
		Checkers: map[string]config.InjectionCheckerConfig{"decide": def, "watch": def},
		Surfaces: map[string]config.InjectionSurfaceConfig{config.InjectionSurfaceMCPToolResult: {Checker: "decide", Mode: config.InjectionModeBlock, Watch: "watch"}},
	}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	wirePromptInjectionAudit(sc, logger)

	item := checker.Item{
		ID: "item", Kind: checker.KindText, Surface: config.InjectionSurfaceMCPToolResult, Transport: "test", Direction: "response",
		ExtractionVersion: "test/v1",
		Parts:             []checker.Part{{ID: "p0", Role: "content", Representation: "original", Text: echoed}},
		OriginalBytes:     int64(len(echoed)), SubmittedBytes: int64(len(echoed)),
		Completeness: &checker.Completeness{Status: checker.Complete},
	}
	if out, ok := sc.AssessInjection(context.Background(), config.InjectionSurfaceMCPToolResult, item); !ok || !out.Finding() {
		t.Fatalf("assessment = %+v ok=%v", out, ok)
	}
	read := func() string {
		data, _ := os.ReadFile(filepath.Clean(path))
		return string(data)
	}
	testwait.For(t, testwait.Deadline(10*time.Second), func() bool {
		log := read()
		return strings.Contains(log, `"watch":true`) && strings.Contains(log, `"checker":"decide"`)
	}, "deciding and watch outcomes were not both audited")
	log := read()
	if strings.Contains(log, echoed) {
		t.Fatalf("audit log carries the checker's echoed reason ID:\n%s", log)
	}
	if !strings.Contains(log, `"reason":"`+scanner.FindingReason+`"`) {
		t.Fatalf("audit log lacks the proxy-owned finding reason:\n%s", log)
	}
}
