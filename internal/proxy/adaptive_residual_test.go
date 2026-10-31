// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
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

// A residual past its deadline must not count toward the next scored signal on
// any writer path, even when no recovery path or sweep has run in between. The
// fresh controls show the same two signals do escalate inside the quiet period,
// and the disabled case shows expiry only applies with adaptive enforcement on.
func TestAdaptiveResidualExpiryBeforePointsOnEveryWriter(t *testing.T) {
	type writer struct {
		name  string
		write func(s *SessionState, cfg *config.Config)
		level func(s *SessionState) int
		score func(s *SessionState) float64
	}
	ep := func(cfg *config.Config) decide.EscalationParams {
		return decide.EscalationParams{Threshold: cfg.AdaptiveEnforcement.EscalationThreshold}
	}
	scopedLevel := func(s *SessionState) int { return s.ScopedEscalationLevel(residualScope) }
	scopedScore := func(s *SessionState) float64 { return s.ScopedThreatScore(residualScope) }
	writers := []writer{
		{
			name: "scoped_wrapper",
			write: func(s *SessionState, cfg *config.Config) {
				recordAdaptiveSignalForScope(s, residualScope, session.SignalBlock, &cfg.AdaptiveEnforcement, &cfg.Airlock, ep(cfg))
			},
			level: scopedLevel, score: scopedScore,
		},
		{
			// Request entry writes the scoped lane directly, not through the wrapper.
			name: "scoped_direct",
			write: func(s *SessionState, cfg *config.Config) {
				recordScopedAdaptiveSignal(s, residualScope, session.SignalBlock, ep(cfg))
			},
			level: scopedLevel, score: scopedScore,
		},
		{
			// MCP listener headers and aggregate CEE write through decide.RecordSignal.
			name: "aggregate_decide",
			write: func(s *SessionState, cfg *config.Config) {
				decide.RecordSignal(s, session.SignalBlock, ep(cfg))
			},
			level: func(s *SessionState) int { return s.EscalationLevel() },
			score: func(s *SessionState) float64 { return s.ThreatScore() },
		},
	}
	for _, w := range writers {
		for _, tt := range []struct {
			name      string
			enabled   bool
			aged      bool
			wantLevel int
			wantScore float64
		}{
			{name: "expired_before_second_signal", enabled: true, aged: true, wantLevel: 0, wantScore: 3},
			{name: "fresh_residual_still_counts", enabled: true, aged: false, wantLevel: 1},
			{name: "disabled_keeps_score", enabled: false, aged: true, wantLevel: 1, wantScore: 6},
		} {
			t.Run(w.name+"/"+tt.name, func(t *testing.T) {
				cfg := config.Defaults()
				cfg.AdaptiveEnforcement.Enabled = true
				cfg.ApplyDefaults()
				sm := NewSessionManager(testSessionConfig(), &cfg.AdaptiveEnforcement, nil)
				t.Cleanup(sm.Close)
				if !tt.enabled {
					disabled := cfg.AdaptiveEnforcement
					disabled.Enabled = false
					sm.adaptiveCfgPtr.Store(&disabled)
				}
				s := sm.GetOrCreate("residual-writer-" + w.name + "-" + tt.name)
				w.write(s, cfg)
				if tt.aged {
					ageAdaptiveResidual(s, 2*adaptiveLevelDuration(&cfg.AdaptiveEnforcement))
				}
				w.write(s, cfg)
				if got := w.level(s); got != tt.wantLevel {
					t.Fatalf("level = %d, want %d (score %g)", got, tt.wantLevel, w.score(s))
				}
				if tt.aged && w.score(s) != tt.wantScore {
					t.Fatalf("score = %g, want %g", w.score(s), tt.wantScore)
				}
			})
		}
	}
}

// Writer-side expiry reads the manager's live configuration, so a reload that
// shortens or lengthens level_duration_seconds governs the next scored signal
// on sessions that already exist, without a recovery path running first.
func TestAdaptiveResidualExpiryBeforePointsFollowsReload(t *testing.T) {
	for _, tt := range []struct {
		name      string
		seconds   int
		wantScore float64
	}{
		{name: "shortened_expires", seconds: 10, wantScore: 3},
		{name: "lengthened_keeps", seconds: 60, wantScore: 6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.ApplyDefaults()
			cfg.AdaptiveEnforcement.EscalationThreshold = 100
			sm := NewSessionManager(testSessionConfig(), &cfg.AdaptiveEnforcement, nil)
			t.Cleanup(sm.Close)
			s := sm.GetOrCreate("residual-writer-reload-" + tt.name)
			s.RecordScopedSignal(residualScope, session.SignalBlock, 100)
			ageAdaptiveResidual(s, 30*time.Second)
			reloaded := cfg.AdaptiveEnforcement
			reloaded.LevelDurationSeconds = tt.seconds
			sm.UpdateConfig(testSessionConfig(), &reloaded, &cfg.Airlock)
			s.RecordScopedSignal(residualScope, session.SignalBlock, 100)
			if got := s.ScopedThreatScore(residualScope); got != tt.wantScore {
				t.Fatalf("scope score = %g, want %g", got, tt.wantScore)
			}
		})
	}
}

func TestAdaptiveResidualExpiryReporting(t *testing.T) {
	for _, path := range []string{"sweep", "request_entry", "aggregate_writer", "scoped_writer", "concurrent_writer", "scoped_recovery"} {
		t.Run(path, func(t *testing.T) {
			cfg := adaptiveConfig()
			m := metrics.New()
			logPath := filepath.Join(t.TempDir(), "audit.jsonl")
			logger, err := audit.New("json", "file", logPath, true, true)
			if err != nil {
				t.Fatal(err)
			}
			defer logger.Close()
			sm := NewSessionManager(testSessionConfig(), &cfg.AdaptiveEnforcement, m, SessionManagerOptions{Logger: logger})
			defer sm.Close()
			s := sm.GetOrCreate("residual-reporting")
			s.RecordScopedSignal(residualScope, session.SignalBlock, 100)
			ageAdaptiveResidual(s, 2*defaultMaxLevelDuration)
			want := 2
			switch path {
			case "sweep":
				sm.sweepDeescalation()
				sm.sweepDeescalation()
			case "request_entry":
				want = 1
				ctx := adaptiveRecoveryContext{requestID: "expiry-request"}
				if changed, _, _ := trySessionRecovery(s, &cfg.AdaptiveEnforcement, ctx); changed {
					t.Fatal("expiry reported a level change")
				}
				trySessionRecovery(s, &cfg.AdaptiveEnforcement, ctx)
			case "aggregate_writer":
				want = 1
				s.RecordSignal(session.SignalBlock, 100)
				s.RecordSignal(session.SignalNearMiss, 100)
			case "scoped_writer":
				s.RecordScopedSignal(residualScope, session.SignalBlock, 100)
				s.RecordScopedSignal(residualScope, session.SignalNearMiss, 100)
			case "concurrent_writer":
				var wg sync.WaitGroup
				for range 4 {
					wg.Go(func() { s.RecordScopedSignal(residualScope, session.SignalNearMiss, 100) })
				}
				wg.Wait()
			case "scoped_recovery":
				want = 1
				if changes := s.TryAutoRecoverScopes(defaultMaxLevelDuration, nil); len(changes) != 0 {
					t.Fatal("expiry reported a scoped level change")
				}
				s.TryAutoRecoverScopes(defaultMaxLevelDuration, nil)
			}
			// Reading the timeline here also detects accidentally emitting under s.mu.
			events := s.RecentEvents()
			if len(events) != want {
				t.Fatalf("expiry events = %d, want %d", len(events), want)
			}
			scopes := map[string]bool{}
			for _, event := range events {
				if event.Kind != "adaptive_deescalate" || event.Type != adaptiveRecoveryResidualExpired || event.Score != 3 || event.Severity != "info" {
					t.Fatalf("expiry event = %+v", event)
				}
				if scopes[event.Target] {
					t.Fatalf("duplicate scope event: %q", event.Target)
				}
				scopes[event.Target] = true
			}
			if want == 2 && (!scopes[""] || !scopes[residualScope]) {
				t.Fatalf("missing expiry scope: %v", scopes)
			}
			data, err := os.ReadFile(filepath.Clean(logPath))
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
			if len(lines) != want {
				t.Fatalf("audit entries = %d, want %d: %s", len(lines), want, data)
			}
			for _, line := range lines {
				var entry map[string]any
				if err := json.Unmarshal(line, &entry); err != nil {
					t.Fatal(err)
				}
				if entry["event"] != "adaptive_recovery" || entry["reason"] != adaptiveRecoveryResidualExpired || entry["previous_score"] != float64(3) || entry["from"] != "normal" || entry["to"] != "normal" || entry["session"] != s.key {
					t.Fatalf("audit entry = %s", line)
				}
				if path == "request_entry" && entry["request_id"] != "expiry-request" {
					t.Fatalf("request attribution lost: %s", line)
				}
			}
			w := httptest.NewRecorder()
			m.PrometheusHandler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
			if !strings.Contains(w.Body.String(), fmt.Sprintf("pipelock_adaptive_residual_expirations_total %d\n", want)) {
				t.Fatalf("expiry counter missing: %s", w.Body.String())
			}
			if strings.Contains(w.Body.String(), `pipelock_session_auto_deescalation_total{`) {
				t.Fatal("expiry counted as level de-escalation")
			}
			if s.EscalationLevel() != 0 || s.EffectiveEscalationLevel(residualScope) != 0 {
				t.Fatal("reporting changed level")
			}
		})
	}
}
