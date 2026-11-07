// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestMCPWatchReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	write := func(enabled bool) {
		t.Helper()
		if err := os.WriteFile(path, fmt.Appendf(nil, "version: 1\nmode: balanced\nwatch_only: %v\n", enabled), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(false)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.FlightRecorder.RequireReceipts = true
	state := startMCPWatchReload(t.Context(), path, cfg, audit.NewNop(), metrics.New(), io.Discard)
	defer state.close()
	<-state.reloader.Ready()
	if !state.reloader.WatchEstablished() {
		t.Fatal("file watch not established")
	}
	opts := mcp.MCPProxyOpts{RequireReceipts: cfg.FlightRecorder.RequireReceipts}
	applyMCPWatchReloadOpts(&opts, state)
	initialHash := opts.PolicyHashFn()
	for _, enabled := range []bool{true, true, false, false} {
		write(enabled)
		testwait.For(t, 5*time.Second, func() bool { return opts.WatchOnlyFn() == enabled }, "watch-only reload did not become %v", enabled)
		if !opts.RequireReceipts || !state.current.Load().FlightRecorder.RequireReceipts {
			t.Fatal("watch reload cleared receipt requirement")
		}
		if (opts.PolicyHashFn() == initialHash) == enabled {
			t.Fatalf("hash does not follow watch mode %v", enabled)
		}
	}
}

func TestMCPWatchRequiredReceiptStartup(t *testing.T) {
	for _, watch := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.WatchOnly = watch
		cfg.FlightRecorder.RequireReceipts = true
		err := validateMCPRequiredReceipts(cfg, nil)
		if err == nil || !strings.Contains(err.Error(), "no healthy signed receipt emitter") {
			t.Fatalf("watch=%v startup error=%v", watch, err)
		}
	}
}

func TestMCPListenerMetadataRefusalEnforced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{logger: logger, metrics: metrics.New()}
	s.recordMCPMetadataRefusal("cloud metadata destination refused")
	logger.Close()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "watch_only_enforced") || !strings.Contains(string(data), `"enforced":true`) {
		t.Fatalf("metadata refusal was logged as observation: %s", data)
	}
}
