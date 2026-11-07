// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	mcpAirlockTriggerElevated = "on_elevated"
	mcpAirlockTriggerHigh     = "on_high"
	mcpAirlockTriggerCritical = "on_critical"
)

// recordMCPAdaptiveSignal records one MCP threat signal and raises the same
// per-client recorder's airlock on escalation edges. Keeping the transition
// edge-bound prevents a timer-deescalated session from being re-armed merely
// because its adaptive level has not yet recovered.
func recordMCPAdaptiveSignal(opts MCPProxyOpts, rec session.Recorder, sig session.SignalType, p decide.EscalationParams) bool {
	if opts.watchOnly() {
		observeWatchMCPSignal(opts, rec, sig, p)
		return false
	}

	if session.ClassifiedDenialSignal(sig) &&
		(p.DenialScanner != "" || p.DenialReason != "") &&
		!session.NoteClassifiedDenial(rec, "", p.DenialScanner, p.DenialReason, p.PolicyHash) {
		return false
	}
	if !decide.RecordSignal(rec, sig, p) {
		return false
	}

	cfg := opts.airlockCfg()
	if cfg == nil || !cfg.Enabled || rec == nil {
		return true
	}

	tier := ""
	trigger := ""
	level := session.EscalationLabel(rec.EscalationLevel())
	switch level {
	case "elevated":
		tier = cfg.Triggers.OnElevated
		trigger = mcpAirlockTriggerElevated
	case "high":
		tier = cfg.Triggers.OnHigh
		trigger = mcpAirlockTriggerHigh
	case "critical":
		tier = cfg.Triggers.OnCritical
		trigger = mcpAirlockTriggerCritical
	}
	if tier == "" || tier == config.AirlockTierNone {
		return true
	}

	if changed, from, to := session.EscalateAirlock(rec, tier, trigger); changed {
		if p.Logger != nil {
			p.Logger.LogAirlockEnter(p.Session, to, "adaptive_"+level, p.ClientIP, p.RequestID)
		}
		if p.Metrics != nil {
			p.Metrics.RecordAirlockTransition(from, to, "adaptive")
		}
	}
	return true
}

// The optional observation recorder reuses the existing scoring rules while
// keeping enforcement score, escalation and airlock state unchanged.
func observeWatchMCPSignal(opts MCPProxyOpts, rec session.Recorder, sig session.SignalType, p decide.EscalationParams) {
	observer, ok := rec.(interface {
		ObserveWatchOnlySignal(string, session.SignalType, *config.AdaptiveEnforcement, decide.EscalationParams) (bool, string, string)
	})
	cfg := opts.adaptiveCfg()
	if !ok || cfg == nil || !cfg.Enabled {
		return
	}
	if escalated, from, to := observer.ObserveWatchOnlySignal("", sig, cfg, p); escalated {
		opts.recordWatch("adaptive", "session would escalate from "+from+" to "+to, "escalate", 0, false)
	}
}

func observeWatchMCPClean(opts MCPProxyOpts) {
	if observer, ok := opts.Rec.(interface {
		ObserveWatchOnlyClean(string, *config.AdaptiveEnforcement)
	}); ok {
		observer.ObserveWatchOnlyClean("", opts.adaptiveCfg())
	}
}
