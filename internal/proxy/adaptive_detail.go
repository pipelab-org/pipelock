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

// adaptiveAudit ties an adaptive explanation's audit copy to the refused
// request. It deliberately omits the URL and target: an upgraded finding may
// have matched content there, and this event is not a content-scanner block.
type adaptiveAudit struct {
	log       *audit.Logger
	clientIP  string
	requestID string
}

func (a adaptiveAudit) logBlocked(layer, detail string) {
	if a.log != nil {
		a.log.LogBlocked(audit.NewClientRequestLogContext("ADAPTIVE", a.clientIP, a.requestID), layer, detail)
	}
}

// Report the enforcement scope's score, not an aggregate from unrelated hosts.
func adaptiveBlockDetail(aa adaptiveAudit, rec session.Recorder, cfg *config.Config, scope, category string) string {
	score, level := adaptiveBlockState(rec, scope)
	detail := decide.AdaptiveBlockDetail(category, score, level, &cfg.AdaptiveEnforcement)
	aa.logBlocked(adaptiveEnforcementLayer, detail)
	return detail
}

// HeaderAdaptiveDetail contains no request content or identity. It supplements
// the existing block-reason vocabulary on HTTP paths whose bodies are fixed.
const headerAdaptiveDetail = "X-Pipelock-Adaptive-Detail"

func setAdaptiveBlockDetail(w http.ResponseWriter, aa adaptiveAudit, rec session.Recorder, cfg *config.Config, scope, category string) {
	w.Header().Set(headerAdaptiveDetail, adaptiveBlockDetail(aa, rec, cfg, scope, category))
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

func adaptiveWSClosePayload(aa adaptiveAudit, rec session.Recorder, cfg *config.Config, scope string, info blockreason.Info) string {
	_ = adaptiveBlockDetail(aa, rec, cfg, scope, string(info.Reason))
	return adaptiveCloseFrame(rec, cfg, scope, info)
}

// adaptiveCloseFrame builds the close payload without an audit copy, for a
// caller that already recorded a more specific explanation.
func adaptiveCloseFrame(rec session.Recorder, cfg *config.Config, scope string, info blockreason.Info) string {
	score, _ := adaptiveBlockState(rec, scope)
	duration := cfg.AdaptiveEnforcement.LevelDurationSeconds
	if duration <= 0 {
		duration = config.Defaults().AdaptiveEnforcement.LevelDurationSeconds
	}
	return info.WithAdaptiveRecovery(score, cfg.AdaptiveEnforcement.EscalationThreshold, duration).CloseFramePayload()
}

func airlockBlockDetail(aa adaptiveAudit, rec session.Recorder, cfg *config.Config, scope, tier string) string {
	score, level := adaptiveBlockState(rec, scope)
	detail := decide.AdaptiveBlockDetail("airlock", score, level, &cfg.AdaptiveEnforcement) + "; " + decide.AirlockRecoveryDetail(tier, &cfg.Airlock)
	aa.logBlocked("airlock", detail)
	return detail
}
