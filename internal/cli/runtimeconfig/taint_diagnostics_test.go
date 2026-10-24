// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtimeconfig

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMCPTaintDiagnostics_OnlySessionModes(t *testing.T) {
	for _, mode := range []config.RuntimeMode{config.RuntimeForward, config.RuntimeForwardWithMCPListener, config.RuntimeMCPProxy, config.RuntimeMCPScan} {
		var log bytes.Buffer
		ResolveAndReportConfig(config.Defaults(), config.RuntimeResolveOpts{Mode: mode}, &log, "test")
		if got := strings.Contains(log.String(), "taint.mcp_listener:"); got != mode.WrapsMCP() {
			t.Fatalf("mode %v diagnostic=%t", mode, got)
		}
	}
	EmitMCPTaintDiagnostics(nil, nil, config.RuntimeMCPProxy)
}
