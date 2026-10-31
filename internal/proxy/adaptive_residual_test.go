// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const residualScope = "api.vendor.example"

func TestAdaptiveResidualExpiryBoundary(t *testing.T) {
	now := time.Now()
	duration := defaultMaxLevelDuration
	old := now.Add(-2 * duration)
	boundary := now.Add(-duration)
	for _, tt := range []struct {
		name           string
		signal, change time.Time
		level          int
		score, want    float64
	}{
		{name: "no_anchor", score: 3, want: 3},
		{name: "before_deadline", signal: boundary.Add(time.Nanosecond), score: 3, want: 3},
		{name: "at_deadline", signal: boundary, score: 3},
		{name: "past_deadline", signal: old, score: 3},
		{name: "recent_signal", signal: now, change: old, score: 3, want: 3},
		{name: "recent_level_change", signal: old, change: now, score: 2.5, want: 2.5},
		{name: "level_change_only", change: boundary, score: 2.5},
		{name: "future_signal", signal: now.Add(duration), score: 3, want: 3},
		{name: "escalated", signal: old, change: old, level: 1, score: 6, want: 6},
		{name: "empty", signal: old},
	} {
		t.Run(tt.name, func(t *testing.T) {
			score := tt.score
			expireAdaptiveResidual(&score, tt.level, tt.signal, tt.change, duration, now)
			if score != tt.want {
				t.Fatalf("score = %g, want %g", score, tt.want)
			}
		})
	}
}

// Age only the timer state, under its production lock. No wall-clock waiting
// or background ticker is needed to exercise the real recovery entry points.
func ageAdaptiveResidual(s *SessionState, age time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := time.Now().Add(-age)
	s.lastSignal = old
	if !s.lastEscalation.IsZero() {
		s.lastEscalation = old
	}
	for _, st := range s.scopes {
		st.lastSignal = old
		if !st.lastEscalation.IsZero() {
			st.lastEscalation = old
		}
	}
}

func TestAdaptiveResidualExpirySweepWithoutTraffic(t *testing.T) {
	cfg := config.Defaults()
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.ApplyDefaults()
	sm := NewSessionManager(testSessionConfig(), &cfg.AdaptiveEnforcement, nil)
	defer sm.Close()
	s := sm.GetOrCreate("residual-idle")
	s.RecordScopedSignal(residualScope, session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
	_, task, _ := s.BeginNewTask("residual expiry")
	s.ObserveRisk(session.ClassifyHTTPResponseObservation("https://untrusted.example/data", "text/plain", nil, true))
	_, _, _ = s.Airlock().SetTier(config.AirlockTierHard)
	_, _, _ = s.AirlockForScope(residualScope).SetTier(config.AirlockTierHard)
	risk := s.RiskSnapshot()
	ageAdaptiveResidual(s, 2*adaptiveLevelDuration(&cfg.AdaptiveEnforcement))
	sm.sweepDeescalation()
	if s.ThreatScore() != 0 || s.ScopedThreatScore(residualScope) != 0 {
		t.Fatalf("idle residual survived sweep: aggregate=%g scope=%g", s.ThreatScore(), s.ScopedThreatScore(residualScope))
	}
	if s.EscalationLevel() != 0 || s.RiskSnapshot().Level != risk.Level || !s.RiskSnapshot().Contaminated || s.TaskSnapshot() != task {
		t.Fatal("residual expiry changed level, taint or task")
	}
	if s.Airlock().Tier() != config.AirlockTierHard || s.AirlockForScope(residualScope).Tier() != config.AirlockTierHard {
		t.Fatal("residual expiry changed airlock state")
	}
	// A second sweep neither recreates score nor changes the threshold.
	sm.sweepDeescalation()
	s.RecordScopedSignal(residualScope, session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
	if s.ThreatScore() != session.SignalPoints[session.SignalBlock] || s.EscalationLevel() != 0 {
		t.Fatal("new signal inherited expired points or a changed threshold")
	}
}

func TestAdaptiveResidualExpiryNewSignalRestarts(t *testing.T) {
	for _, scope := range []string{"", residualScope} {
		for _, sig := range []session.SignalType{session.SignalNearMiss, session.SignalShieldRewrite} {
			t.Run(fmt.Sprintf("%s/%d", scope, sig), func(t *testing.T) {
				s := &SessionState{}
				s.RecordScopedSignal(scope, session.SignalBlock, 5)
				ageAdaptiveResidual(s, 2*defaultMaxLevelDuration)
				s.RecordScopedSignal(scope, sig, 5)
				want := session.SignalPoints[session.SignalBlock] + session.SignalPoints[sig]
				if changed, _, _ := s.TryAutoRecover(defaultMaxLevelDuration, nil); changed {
					t.Fatal("residual expiry reported a level transition")
				}
				if changes := s.TryAutoRecoverScopes(defaultMaxLevelDuration, nil); len(changes) != 0 {
					t.Fatal("residual expiry reported a scoped level transition")
				}
				if s.ThreatScore() != want || s.ScopedThreatScore(scope) != want {
					t.Fatalf("new signal did not restart timer: aggregate=%g scope=%g want=%g", s.ThreatScore(), s.ScopedThreatScore(scope), want)
				}
				ageAdaptiveResidual(s, 2*defaultMaxLevelDuration)
				s.TryAutoRecover(defaultMaxLevelDuration, nil)
				s.TryAutoRecoverScopes(defaultMaxLevelDuration, nil)
				if s.ThreatScore() != 0 || s.ScopedThreatScore(scope) != 0 {
					t.Fatal("residual did not expire after a full quiet interval")
				}
			})
		}
	}
}

// Warnings and unknown signal types contribute no points. Neither may postpone
// expiry, even when observations continue through the original deadline.
func TestAdaptiveResidualExpiryZeroPointSignals(t *testing.T) {
	for _, scope := range []string{"", residualScope} {
		for _, sig := range []session.SignalType{session.SignalWarning, session.SignalType(-1)} {
			t.Run(fmt.Sprintf("%s/%d", scope, sig), func(t *testing.T) {
				s := &SessionState{}
				s.RecordScopedSignal(scope, session.SignalBlock, 5)
				anchor := time.Now().Add(-2 * defaultMaxLevelDuration)
				s.mu.Lock()
				s.lastSignal = anchor
				if scope != "" {
					s.scopes[scope].lastSignal = anchor
				}
				s.mu.Unlock()
				for _, elapsed := range []time.Duration{defaultMaxLevelDuration / 2, defaultMaxLevelDuration - time.Nanosecond, defaultMaxLevelDuration} {
					s.RecordScopedSignal(scope, sig, 5)
					s.mu.Lock()
					if !s.lastSignal.Equal(anchor) || (scope != "" && !s.scopes[scope].lastSignal.Equal(anchor)) {
						t.Error("zero-point signal restarted residual timer")
					}
					now := anchor.Add(elapsed)
					expireAdaptiveResidual(&s.threatScore, s.escalationLevel, s.lastSignal, s.lastEscalation, defaultMaxLevelDuration, now)
					if scope != "" {
						st := s.scopes[scope]
						expireAdaptiveResidual(&st.threatScore, st.escalationLevel, st.lastSignal, st.lastEscalation, defaultMaxLevelDuration, now)
					}
					s.mu.Unlock()
					want := session.SignalPoints[session.SignalBlock]
					if elapsed == defaultMaxLevelDuration {
						want = 0
					}
					if s.ThreatScore() != want || s.ScopedThreatScore(scope) != want {
						t.Fatalf("zero-point stream at %s: aggregate=%g scope=%g want=%g", elapsed, s.ThreatScore(), s.ScopedThreatScore(scope), want)
					}
				}
			})
		}
	}
}

func TestAdaptiveResidualExpiryAfterDeescalation(t *testing.T) {
	for _, cleanRecovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("clean=%t", cleanRecovery), func(t *testing.T) {
			s := &SessionState{}
			s.RecordScopedSignal(residualScope, session.SignalBlock, 5)
			s.RecordScopedSignal(residualScope, session.SignalBlock, 5)
			ageAdaptiveResidual(s, 2*defaultMaxLevelDuration)
			if cleanRecovery {
				s.RecordCleanWithRecovery(0, 1, nil)
				s.RecordScopedCleanWithRecovery(residualScope, 0, 1, nil)
			} else {
				s.TryAutoRecover(defaultMaxLevelDuration, nil)
				s.TryAutoRecoverScopes(defaultMaxLevelDuration, nil)
			}
			if s.EscalationLevel() != 0 || s.ThreatScore() != 2.5 || s.ScopedThreatScore(residualScope) != 2.5 {
				t.Fatal("de-escalation did not leave the existing threshold/2 residual")
			}
			// The old signal is expired, but the new level change starts a
			// fresh interval for the residual. Repeated checks cannot erase it.
			s.TryAutoRecover(defaultMaxLevelDuration, nil)
			s.TryAutoRecoverScopes(defaultMaxLevelDuration, nil)
			if s.ThreatScore() != 2.5 || s.ScopedThreatScore(residualScope) != 2.5 {
				t.Fatal("residual expired immediately after de-escalation")
			}
			ageAdaptiveResidual(s, 2*defaultMaxLevelDuration)
			s.TryAutoRecover(defaultMaxLevelDuration, nil)
			s.TryAutoRecoverScopes(defaultMaxLevelDuration, nil)
			if s.ThreatScore() != 0 || s.ScopedThreatScore(residualScope) != 0 {
				t.Fatal("post-de-escalation residual did not expire")
			}
		})
	}
}

func TestAdaptiveResidualExpiryScopeIndependence(t *testing.T) {
	const recentScope = "recent.vendor.example"
	s := &SessionState{}
	s.RecordScopedSignal(residualScope, session.SignalNearMiss, 5)
	ageAdaptiveResidual(s, 2*defaultMaxLevelDuration)
	s.RecordScopedSignal(recentScope, session.SignalNearMiss, 5)
	s.TryAutoRecover(defaultMaxLevelDuration, nil)
	s.TryAutoRecoverScopes(defaultMaxLevelDuration, nil)
	if s.ScopedThreatScore(residualScope) != 0 || s.ScopedThreatScore(recentScope) != 1 || s.ThreatScore() != 2 {
		t.Fatal("expired scope lowered another scope or the recently signaled aggregate")
	}
	// Conversely, aggregate expiry must not erase a scope with a newer
	// level change (for example, after scoped clean-streak recovery).
	s.mu.Lock()
	s.lastSignal = time.Now().Add(-2 * defaultMaxLevelDuration)
	s.mu.Unlock()
	s.TryAutoRecover(defaultMaxLevelDuration, nil)
	if s.ThreatScore() != 0 || s.ScopedThreatScore(recentScope) != 1 {
		t.Fatal("aggregate expiry changed scoped score")
	}
}

func TestAdaptiveResidualExpiryReload(t *testing.T) {
	for _, tt := range []struct {
		name          string
		initial, next int
		want          float64
	}{
		{"first_load", 300, 0, 0},
		{"reload_shorter", 600, 300, 0},
		{"reload_longer", 300, 600, 3},
		{"reload_unchanged_expired", 300, 300, 0},
		{"reload_unchanged_recent", 600, 600, 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			load := func(seconds int) *config.Config {
				t.Helper()
				cfg, err := config.LoadBytes(fmt.Appendf(nil, "session_profiling: {enabled: true}\nadaptive_enforcement: {enabled: true, level_duration_seconds: %d}", seconds))
				if err != nil {
					t.Fatal(err)
				}
				return cfg
			}
			cfg := load(tt.initial)
			sm := NewSessionManager(testSessionConfig(), &cfg.AdaptiveEnforcement, nil)
			defer sm.Close()
			s := sm.GetOrCreate("residual-reload")
			s.RecordScopedSignal(residualScope, session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
			ageAdaptiveResidual(s, 450*time.Second)
			if tt.next != 0 {
				next := load(tt.next)
				sm.UpdateConfig(testSessionConfig(), &next.AdaptiveEnforcement, nil)
			}
			sm.sweepDeescalation()
			if s.ThreatScore() != tt.want || s.ScopedThreatScore(residualScope) != tt.want || sm.GetOrCreate("residual-reload") != s {
				t.Fatalf("reload recovery: aggregate=%g scope=%g want=%g", s.ThreatScore(), s.ScopedThreatScore(residualScope), tt.want)
			}
		})
	}
}

func TestAdaptiveResidualExpiryDisabled(t *testing.T) {
	for _, yaml := range []string{"{}", "adaptive_enforcement: {}", "adaptive_enforcement: {enabled: null}", "adaptive_enforcement: {enabled: }", "adaptive_enforcement: {enabled: false}"} {
		t.Run(yaml, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(yaml))
			if err != nil {
				t.Fatal(err)
			}
			sm := NewSessionManager(testSessionConfig(), &cfg.AdaptiveEnforcement, nil)
			defer sm.Close()
			s := sm.GetOrCreate("residual-disabled")
			s.RecordScopedSignal(residualScope, session.SignalBlock, 5)
			ageAdaptiveResidual(s, 2*defaultMaxLevelDuration)
			sm.sweepDeescalation()
			trySessionRecovery(s, &cfg.AdaptiveEnforcement, adaptiveRecoveryContext{})
			if s.ThreatScore() != 3 || s.ScopedThreatScore(residualScope) != 3 {
				t.Fatal("disabled adaptive expired score")
			}
			// A reload disabling adaptive must preserve residuals too.
			enabled := cfg.AdaptiveEnforcement
			enabled.Enabled = true
			sm.UpdateConfig(testSessionConfig(), &enabled, nil)
			sm.UpdateConfig(testSessionConfig(), &cfg.AdaptiveEnforcement, nil)
			sm.sweepDeescalation()
			sm.UpdateConfig(testSessionConfig(), nil, nil)
			sm.sweepDeescalation()
			if s.ThreatScore() != 3 || s.ScopedThreatScore(residualScope) != 3 {
				t.Fatal("disabled reload expired score")
			}
		})
	}
}

func TestAdaptiveResidualExpiryResetAndEntry(t *testing.T) {
	s := &SessionState{}
	s.RecordSignal(session.SignalBlock, 5)
	ageAdaptiveResidual(s, 2*defaultMaxLevelDuration)
	trySessionRecovery(s, &config.AdaptiveEnforcement{Enabled: true}, adaptiveRecoveryContext{})
	if s.ThreatScore() != 0 {
		t.Fatal("on-entry recovery did not expire residual")
	}
	s.RecordScopedSignal(residualScope, session.SignalNearMiss, 5)
	s.Reset(false)
	s.mu.Lock()
	if !s.lastSignal.IsZero() || !s.lastEscalation.IsZero() || len(s.scopes) != 0 {
		t.Error("reset retained residual timestamps or scopes")
	}
	s.mu.Unlock()
	s.RecordSignal(session.SignalBlock, 5)
	s.TryAutoRecover(0, nil)
	if s.ThreatScore() != 3 {
		t.Fatal("signal after reset expired early")
	}
}
