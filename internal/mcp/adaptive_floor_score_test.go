// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// A floor that refuses under a warn-configured action is a real block, not an
// upgraded warning. Upgraded warnings score zero only because each site reads
// its scoring origin after the floor has raised the action; these cases fail
// if a site reads the configured action instead.
func TestAdaptiveWarnConfiguredFloorBlocksStillScore(t *testing.T) {
	for _, stage := range []string{"input_stdio", "input_http", "tool_capacity"} {
		for _, level := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/level=%d", stage, level), func(t *testing.T) {
				cfg := config.Defaults()
				cfg.AdaptiveEnforcement.Enabled = true
				cfg.ApplyDefaults()
				cfg.Internal = nil
				sc := scanner.MustNew(cfg)
				defer sc.Close()
				rec := &mockRecorder{level: level, score: 6}
				before := rec.ThreatScore()
				opts := MCPProxyOpts{Scanner: sc, Rec: rec, AdaptiveCfg: &cfg.AdaptiveEnforcement, InputCfg: newHTTPInputCfg(config.ActionWarn)}
				var out, log bytes.Buffer
				switch stage {
				case "input_stdio", "input_http":
					msg := makeRequest(904, methodToolsCall, map[string]interface{}{"name": "safe_tool", "arguments": map[string]string{"token": mcpSyntheticAWSAccessKey()}})
					if stage == "input_http" {
						if scanHTTPInput([]byte(msg), &log, "test-session", "test-session", opts) == nil {
							t.Fatal("core credential was forwarded")
						}
					} else {
						blockedCh := make(chan BlockedRequest, 2)
						ForwardScannedInput(transport.NewStdioReader(strings.NewReader(msg+"\n")), transport.NewStdioWriter(&out), &log, config.ActionWarn, config.ActionBlock, blockedCh, nil, nil, opts)
						if len(blockedCh) != 1 || out.Len() != 0 {
							t.Fatalf("blocks=%d forwarded=%s log=%s", len(blockedCh), out.String(), log.String())
						}
					}
				case "tool_capacity":
					opts.ToolCfg = &tools.ToolScanConfig{Action: config.ActionWarn, Baseline: tools.NewToolBaseline()}
					line := string(makeToolsResponse(`null`)) + "\n"
					if _, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(line)), transport.NewStdioWriter(&out), &log, nil, opts); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(out.String(), malformedShapeLimit) {
						t.Fatalf("uninspectable tools/list was not refused: %s", out.String())
					}
				}
				if rec.ThreatScore() <= before {
					t.Fatalf("floor block under warn action added no points: before=%.1f after=%.1f signals=%v", before, rec.ThreatScore(), rec.signals)
				}
				for _, sig := range rec.signals {
					if sig == session.SignalWarning {
						t.Fatalf("floor block recorded as a warning: signals=%v", rec.signals)
					}
				}
				t.Logf("score=%.1f -> %.1f signals=%v", before, rec.ThreatScore(), rec.signals)
			})
		}
	}
}
