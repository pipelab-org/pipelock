// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A core credential split across MCP requests is refused when
// cross_request_detection.action is warn. The operator log names the core
// pattern and says it cannot be downgraded.
func TestCeeRecordMCP_CoreFragmentWarnRefused(t *testing.T) {
	fb := scanner.NewFragmentBuffer(65536, 1000, testMCPWindowSecs)
	t.Cleanup(fb.Close)
	sc := testMCPScanner()
	t.Cleanup(sc.Close)
	cee := &CEEDeps{
		Buffer: fb, Metrics: metrics.New(),
		Config: &config.CrossRequestDetection{
			FragmentReassembly: config.CrossRequestFragments{Enabled: true, MaxBufferBytes: 65536, WindowMinutes: testMCPWindowSecs / 60},
			Action:             config.ActionWarn,
		},
	}
	var logBuf bytes.Buffer
	logger := audit.NewNop()
	prefix := "AKIA" + "QRST"
	suffix := "UVWXYZ2345678901"
	if reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: []byte(prefix),
		fragmentPayloads: map[string][]byte{"": []byte(prefix)},
		cee:              cee, sc: sc, logW: &logBuf, logger: logger,
	}); reason != "" {
		t.Fatalf("prefix blocked: %q", reason)
	}
	var matched string
	reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: testMCPSessionKey, entropyPayload: []byte(suffix),
		fragmentPayloads: map[string][]byte{"": []byte(suffix)},
		cee:              cee, sc: sc, logW: &logBuf, logger: logger,
		matchedPattern: &matched,
	})
	if reason != ceeFragmentBlockClientReason || matched != "AWS Access ID" {
		t.Fatalf("reassembled core credential reason=%q pattern=%q, want a blocked core fragment", reason, matched)
	}
	if !strings.Contains(logBuf.String(), "core pattern cannot be downgraded") || !strings.Contains(logBuf.String(), "AWS Access ID") {
		t.Fatalf("operator log = %q, want a core floor refusal", logBuf.String())
	}
}
