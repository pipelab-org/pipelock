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
