// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// mcpWatchReload joins the config file/signal reloader for the watch-only switch.
// Other standalone MCP settings retain their existing restart requirement.
// The hash describes the effective startup policy plus the current switch.
type mcpWatchReload struct {
	mu            sync.RWMutex
	current       atomic.Pointer[config.Config]
	reloader      *config.Reloader
	done          chan struct{}
	generation    uint64
	resetAdaptive func()
}

func startMCPWatchReload(ctx context.Context, path string, cfg *config.Config, logger *audit.Logger, m *metrics.Metrics, logW io.Writer) *mcpWatchReload {
	state := &mcpWatchReload{done: make(chan struct{})}
	state.current.Store(cfg.Clone())
	if cfg.WatchOnly {
		logger.LogWatchOnlyMode(true)
	}
	m.SetWatchOnly(cfg.WatchOnly)
	if path == "" {
		close(state.done)
		return state
	}
	state.reloader = config.NewReloader(path)
	go func() {
		defer close(state.done)
		errCh := make(chan error, 1)
		go func() { errCh <- state.reloader.Start(ctx) }()
		for event := range state.reloader.Reloads() {
			if event.Err != nil || event.Config == nil {
				continue
			}
			old := state.current.Load()
			if old.WatchOnly == event.Config.WatchOnly {
				continue
			}
			updated := old.Clone()
			updated.WatchOnly = event.Config.WatchOnly
			state.mu.Lock()
			state.generation++
			if state.resetAdaptive != nil {
				state.resetAdaptive()
			}
			state.current.Store(updated)
			state.mu.Unlock()
			logger.LogWatchOnlyMode(updated.WatchOnly)
			m.SetWatchOnly(updated.WatchOnly)
		}
		if err := <-errCh; err != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: MCP watch-only reload unavailable: %v\n", err)
		}
	}()
	<-state.reloader.Ready()
	return state
}

func (s *mcpWatchReload) close() {
	if s.reloader != nil {
		s.reloader.Close()
	}
	<-s.done
}

func applyMCPWatchReloadOpts(opts *mcp.MCPProxyOpts, state *mcpWatchReload) {
	state.mu.Lock()
	if resetter, ok := opts.Store.(interface{ ResetWatchOnlyAdaptive() }); ok {
		state.resetAdaptive = resetter.ResetWatchOnlyAdaptive
	} else if resetter, ok := opts.Rec.(interface{ ResetWatchOnlyAdaptive() }); ok {
		state.resetAdaptive = resetter.ResetWatchOnlyAdaptive
	}
	state.mu.Unlock()
	opts.WatchOnlyGenerationFn = func() uint64 { return state.generation }
	opts.PolicyConfigFn = state.current.Load
	opts.ReloadMu = &state.mu
	opts.WatchOnlyFn = func() bool { return state.current.Load().WatchOnly }
	opts.PolicyHashFn = func() string { return state.current.Load().CanonicalPolicyHash() }
	opts.ConfigHashFn = opts.PolicyHashFn
}
