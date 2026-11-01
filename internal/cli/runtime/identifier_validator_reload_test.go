// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestIdentifierValidatorReloadRejection(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mode       string
		receipts   bool
		wantReject bool
	}{
		{"balanced", config.ModeBalanced, false, false},
		{"strict", config.ModeStrict, false, true},
		{"required receipts", config.ModeBalanced, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := config.Defaults()
			old.Mode = tt.mode
			old.FlightRecorder.RequireReceipts = tt.receipts
			old.DLP.Patterns = []config.DLPPattern{{Name: "identifier", Regex: `\b[ABFMPRSX][A-Z9]\d{7}\b`, Severity: config.SeverityCritical}}
			next := old.Clone()
			next.DLP.Patterns[0].Validator = config.ValidatorDEA
			reason := reloadDowngradeRejectReason(old, next, config.ValidateReload(old, next))
			if (reason != "") != tt.wantReject {
				t.Fatalf("reload rejection=%q, want reject=%v", reason, tt.wantReject)
			}
			if reason := reloadDowngradeRejectReason(next, next.Clone(), config.ValidateReload(next, next.Clone())); reason != "" {
				t.Fatalf("unchanged validator rejected: %s", reason)
			}
		})
	}
}
