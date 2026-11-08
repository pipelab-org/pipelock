// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// deferredWatchConfig preserves normal enforcement for surfaces that do not
// yet support watch-only. The configured snapshot is never mutated.
func deferredWatchConfig(cfg *config.Config) *config.Config {
	if cfg == nil || !cfg.WatchOnly {
		return cfg
	}
	effective := cfg.Clone()
	effective.WatchOnly = false
	return effective
}

// admittedWatchConfig keeps watch-only semantics for a request admitted under
// them after a reload turned the mode off. The configured snapshot is never
// mutated.
func admittedWatchConfig(cfg *config.Config) *config.Config {
	if cfg == nil || cfg.WatchOnly {
		return cfg
	}
	effective := cfg.Clone()
	effective.WatchOnly = true
	return effective
}

func watchRequestConfig(cfg *config.Config, r *http.Request) *config.Config {
	if r.Method == http.MethodConnect || (!r.URL.IsAbs() && r.URL.Path == "/ws") {
		return deferredWatchConfig(cfg)
	}
	return cfg
}
