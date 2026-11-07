// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	state := startMCPWatchReload(t.Context(), path, cfg, audit.NewNop(), metrics.New(), io.Discard)
	defer state.close()
	<-state.reloader.Ready()
	if !state.reloader.WatchEstablished() {
		t.Fatal("file watch not established")
	}
	var opts mcp.MCPProxyOpts
	applyMCPWatchReloadOpts(&opts, state)
	initialHash := opts.PolicyHashFn()
	for _, enabled := range []bool{true, true, false, false} {
		write(enabled)
		testwait.For(t, 5*time.Second, func() bool { return opts.WatchOnlyFn() == enabled }, "watch-only reload did not become %v", enabled)
		if (opts.PolicyHashFn() == initialHash) == enabled {
			t.Fatalf("hash does not follow watch mode %v", enabled)
		}
	}
}
