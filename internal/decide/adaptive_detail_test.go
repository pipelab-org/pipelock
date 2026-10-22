// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAdaptiveBlockDetail(t *testing.T) {
	for _, cfg := range []*config.AdaptiveEnforcement{nil, {}, {EscalationThreshold: 7, LevelDurationSeconds: 42, DecayPerCleanRequest: 0.25, CleanRequestsToDeescalate: 8}} {
		got := AdaptiveBlockDetail("mcp_input", 9, 2, cfg)
		for _, want := range []string{`category="mcp_input"`, "score=9", "escalation_threshold=", "level=high", "recovery:", "per level", "clean_request_decay=", "clean_requests_to_deescalate="} {
			if !strings.Contains(got, want) {
				t.Errorf("detail %q missing %q", got, want)
			}
		}
		if cfg != nil && cfg.LevelDurationSeconds == 42 && !strings.Contains(got, "wait 42s") {
			t.Errorf("detail ignores configured recovery: %q", got)
		}
	}
}

func TestAirlockRecoveryDetail(t *testing.T) {
	if got := AirlockRecoveryDetail("hard", nil); !strings.Contains(got, "operator session reset required") {
		t.Fatal(got)
	}
	cfg := &config.Airlock{Timers: config.AirlockTimers{SoftMinutes: 2, HardMinutes: 3, DrainMinutes: 4, DrainTimeoutSeconds: 5}}
	got := AirlockRecoveryDetail("hard", cfg)
	for _, want := range []string{`tier="hard"`, "soft_minutes=2", "hard_minutes=3", "drain_minutes=4", "drain_timeout_seconds=5", "zero disables"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s: %s", want, got)
		}
	}
}
