// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSandboxProxyUsesInvocationRecorder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sandbox subprocess fixture requires /bin/echo")
	}
	for _, tc := range []struct {
		name      string
		external  bool
		fromStore bool
		level     session.TaintLevel
	}{
		{name: "external", external: true, level: session.TaintExternalUntrusted},
		{name: "undeclared", level: session.TaintInternalGenerated},
		{name: "store_owned", external: true, fromStore: true, level: session.TaintExternalUntrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &taintRecorder{}
			var output, logs bytes.Buffer
			cmd := exec.CommandContext(t.Context(), "/bin/echo", cleanResponse)
			opts := MCPProxyOpts{
				Scanner: testScannerWithAction(t, config.ActionWarn), Rec: rec,
				TaintCfg: &cfg.Taint, TaintExternalSource: tc.external,
			}
			if tc.fromStore {
				opts.Rec = nil
				opts.Store = findingRecorderStore{rec: rec}
			}
			err := RunProxyWithSandbox(t.Context(), cmd, strings.NewReader(""), &output, &logs, opts)
			if err != nil {
				t.Fatalf("sandbox proxy: %v; logs=%s", err, &logs)
			}
			if got := rec.RiskSnapshot().Level; got != tc.level {
				t.Fatalf("invocation recorder level=%s want=%s; output=%s", got, tc.level, &output)
			}
		})
	}
}
