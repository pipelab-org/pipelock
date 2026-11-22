// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Widening forward_proxy.connect_ports follows the optional-list contract:
// rejected in strict mode or under a required contract, applied with a
// warning otherwise. Tightening is never refused.
func TestConnectPortsReloadDecision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       string
		required   bool
		old, new   []int
		wantReject bool
	}{
		{name: "balanced_widen_applies", mode: config.ModeBalanced, old: []int{443}, new: []int{443, 22}},
		{name: "balanced_clear_applies", mode: config.ModeBalanced, old: []int{443}, new: nil},
		{name: "strict_widen_rejected", mode: config.ModeStrict, old: []int{443}, new: []int{443, 22}, wantReject: true},
		{name: "strict_clear_rejected", mode: config.ModeStrict, old: []int{443}, new: nil, wantReject: true},
		{name: "required_receipts_widen_rejected", mode: config.ModeBalanced, required: true, old: []int{443}, new: []int{443, 22}, wantReject: true},
		{name: "strict_tighten_applies", mode: config.ModeStrict, old: nil, new: []int{443}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldCfg, newCfg := config.Defaults(), config.Defaults()
			oldCfg.Mode, newCfg.Mode = tc.mode, tc.mode
			oldCfg.FlightRecorder.RequireReceipts, newCfg.FlightRecorder.RequireReceipts = tc.required, tc.required
			oldCfg.ForwardProxy.ConnectPorts = tc.old
			newCfg.ForwardProxy.ConnectPorts = tc.new
			reason := reloadDowngradeRejectReason(oldCfg, newCfg, config.ValidateReload(oldCfg, newCfg))
			if (reason != "") != tc.wantReject {
				t.Fatalf("reject reason=%q, want reject=%v", reason, tc.wantReject)
			}
		})
	}
}
