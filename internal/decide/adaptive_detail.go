// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// AdaptiveBlockDetail explains an adaptive decision without including request
// content. Threshold is the configured initial threshold, not the next edge.
// Recovery takes one level per configured duration; score decay alone does not
// clear an active level. This detail is for operator diagnostics only.
func AdaptiveBlockDetail(category string, score float64, level int, cfg *config.AdaptiveEnforcement) string {
	if cfg == nil {
		defaults := config.Defaults()
		defaults.AdaptiveEnforcement.Enabled = true
		defaults.ApplyDefaults()
		cfg = &defaults.AdaptiveEnforcement
	}
	duration := cfg.LevelDurationSeconds
	if duration <= 0 {
		defaults := config.Defaults()
		defaults.AdaptiveEnforcement.Enabled = true
		defaults.ApplyDefaults()
		duration = defaults.AdaptiveEnforcement.LevelDurationSeconds
	}
	return fmt.Sprintf("blocked by adaptive enforcement (category=%q score=%g escalation_threshold=%g level=%s); recovery: wait %ds without a new escalation per level until the blocking level clears; clean_request_decay=%g clean_requests_to_deescalate=%d",
		category, score, cfg.EscalationThreshold, session.EscalationLabel(level), duration, cfg.DecayPerCleanRequest, cfg.CleanRequestsToDeescalate)
}

// AdaptiveBlockMessage explains a refusal without exposing enforcement state.
func AdaptiveBlockMessage(category string) string {
	return fmt.Sprintf("blocked by adaptive enforcement (category=%q); recovery: ask the operator to inspect or reset the session", category)
}

// AirlockRecoveryDetail reports the separate quarantine timers. Zero disables a
// tier timer; adaptive score decay cannot release that tier by itself.
func AirlockRecoveryDetail(tier string, cfg *config.Airlock) string {
	if cfg == nil {
		return "airlock recovery unavailable; operator session reset required"
	}
	return fmt.Sprintf("airlock tier=%q recovery timers: soft_minutes=%d hard_minutes=%d drain_minutes=%d drain_timeout_seconds=%d; zero disables that timer; wait for tier recovery or operator session reset", tier,
		cfg.Timers.SoftMinutes, cfg.Timers.HardMinutes, cfg.Timers.DrainMinutes, cfg.Timers.DrainTimeoutSeconds)
}
