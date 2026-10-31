// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestUploadInspectionAdaptiveWarningPolicy(t *testing.T) {
	cfg := config.Defaults()
	cfg.AdaptiveEnforcement.Enabled = true
	block := config.ActionBlock
	cfg.AdaptiveEnforcement.Levels.High.UpgradeWarn = &block
	// decide.UpgradeAction documents 2 as the existing high session level.
	const highLevel = 2
	for _, tc := range []struct {
		name   string
		change func(*BodyScanResult)
		want   string
	}{
		{"file observation", func(*BodyScanResult) {}, config.ActionWarn},
		{"credential finding", func(r *BodyScanResult) { r.DLPMatches = []scanner.TextDLPMatch{{PatternName: "custom credential"}} }, config.ActionBlock},
		{"injection finding", func(r *BodyScanResult) { r.InjectionMatches = []scanner.ResponseMatch{{}} }, config.ActionBlock},
		{"enforced file block", func(r *BodyScanResult) { r.Action = config.ActionBlock; r.FileInspectionBlock = true }, config.ActionBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := BodyScanResult{Action: config.ActionWarn, FileInspectionIncomplete: "RAR upload not fully read", Reason: "RAR upload not fully read"}
			tc.change(&r)
			action := r.Action
			if !isBodyAdaptiveExempt(scannerLabelBodyDLP, r, "upload.vendor.example", cfg) {
				action = decide.UpgradeAction(action, highLevel, &cfg.AdaptiveEnforcement)
			}
			if action != tc.want {
				t.Fatalf("file-only warning must preserve delivery without exempting other findings: action=%s want=%s", action, tc.want)
			}
		})
	}
}

func TestUploadInspectionAdaptiveWebSocketPolicy(t *testing.T) {
	// Existing relay helper provisions the documented high adaptive level.
	relay, _ := newAdaptiveWSRelay(t, 2)
	result := BodyScanResult{Action: config.ActionWarn, FileInspectionIncomplete: "RAR upload not fully read", Reason: "RAR upload not fully read"}
	if relay.handleClientMessageBodyResult(audit.NewNop(), []byte("opaque"), result) {
		t.Fatal("file-only observation was promoted to a relay block")
	}
}
