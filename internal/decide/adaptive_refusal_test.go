// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAdaptiveRefusal(t *testing.T) {
	disabled := defaultAdaptiveConfig()
	disabled.Enabled = false

	tests := []struct {
		name  string
		level int
		cfg   *config.AdaptiveEnforcement
		want  bool
	}{
		{name: "nil config", level: 3, cfg: nil},
		{name: "disabled", level: 3, cfg: disabled},
		{name: "normal", level: 0, cfg: defaultAdaptiveConfig()},
		{name: "high without block_all", level: 2, cfg: defaultAdaptiveConfig()},
		{name: "critical with block_all", level: 3, cfg: defaultAdaptiveConfig(), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, message, ok := AdaptiveRefusal(tt.level, tt.cfg)
			if ok != tt.want {
				t.Fatalf("AdaptiveRefusal ok = %v, want %v", ok, tt.want)
			}
			if !ok {
				if info != (blockreason.Info{}) || message != "" {
					t.Fatalf("no projection returned info=%+v message=%q", info, message)
				}
				return
			}
			if info.Reason != blockreason.EscalationLevel || info.Layer != "session_deny" {
				t.Fatalf("projection info = %+v, want escalation_level/session_deny", info)
			}
			if message != AdaptiveBlockMessage("session_deny") {
				t.Fatalf("projection message = %q", message)
			}
		})
	}
}
