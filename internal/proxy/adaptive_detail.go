// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// Report the enforcement scope's score, not an aggregate from unrelated hosts.
func adaptiveBlockDetail(log *audit.Logger, rec session.Recorder, cfg *config.Config, scope, category string) string {
	score, level := adaptiveBlockState(rec, scope)
	detail := decide.AdaptiveBlockDetail(category, score, level, &cfg.AdaptiveEnforcement)
	if log != nil {
		log.LogBlocked(audit.NewMethodLogContext("ADAPTIVE"), adaptiveEnforcementLayer, detail)
	}
	return detail
}

// HeaderAdaptiveDetail contains no request content or identity. It supplements
// the existing block-reason vocabulary on HTTP paths whose bodies are fixed.
const headerAdaptiveDetail = "X-Pipelock-Adaptive-Detail"

func setAdaptiveBlockDetail(w http.ResponseWriter, log *audit.Logger, rec session.Recorder, cfg *config.Config, scope, category string) {
	w.Header().Set(headerAdaptiveDetail, adaptiveBlockDetail(log, rec, cfg, scope, category))
}

func adaptiveBlockState(rec session.Recorder, scope string) (float64, int) {
	var score float64
	var level int
	if s, ok := rec.(*SessionState); ok {
		if s == nil {
			return 0, 0
		}
		s.mu.Lock()
		if st := s.scopes[normalizeAdaptiveScope(scope)]; st != nil {
			score, level = st.threatScore, st.escalationLevel
		}
		if scope == "" || (s.globalSignalsAuthoritative && s.escalationLevel > level) {
			score, level = s.threatScore, s.escalationLevel
		}
		s.mu.Unlock()
	} else if rec != nil {
		score, level = rec.ThreatScore(), rec.EscalationLevel()
	}
	return score, level
}

func adaptiveWSClosePayload(log *audit.Logger, rec session.Recorder, cfg *config.Config, scope string, info blockreason.Info) string {
	_ = adaptiveBlockDetail(log, rec, cfg, scope, string(info.Reason))
	score, _ := adaptiveBlockState(rec, scope)
	duration := cfg.AdaptiveEnforcement.LevelDurationSeconds
	if duration <= 0 {
		duration = config.Defaults().AdaptiveEnforcement.LevelDurationSeconds
	}
	return info.WithAdaptiveRecovery(score, cfg.AdaptiveEnforcement.EscalationThreshold, duration).CloseFramePayload()
}

func airlockBlockDetail(log *audit.Logger, rec session.Recorder, cfg *config.Config, scope, tier string) string {
	score, level := adaptiveBlockState(rec, scope)
	detail := decide.AdaptiveBlockDetail("airlock", score, level, &cfg.AdaptiveEnforcement) + "; " + decide.AirlockRecoveryDetail(tier, &cfg.Airlock)
	if log != nil {
		log.LogBlocked(audit.NewMethodLogContext("ADAPTIVE"), "airlock", detail)
	}
	return detail
}
