// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func watchAdaptiveConfig() *config.AdaptiveEnforcement {
	cfg := config.Defaults().AdaptiveEnforcement
	cfg.Enabled = true
	cfg.EscalationThreshold = 2 * session.SignalPoints[session.SignalBlock]
	return &cfg
}

func TestWatchOnlyAdaptiveMatchesExistingScoring(t *testing.T) {
	for _, scope := range []string{"", "api.vendor.example"} {
		t.Run(scope, func(t *testing.T) {
			cfg := watchAdaptiveConfig()
			observed, enforced := &SessionState{}, &SessionState{}
			initialAirlock := observed.AirlockTier()
			for i, sig := range []session.SignalType{
				session.SignalBlock, session.SignalWarning, session.SignalBlock,
				session.SignalBlock, session.SignalStrip, session.SignalNearMiss,
			} {
				reason := fmt.Sprintf("finding-%d", i)
				if i == 3 {
					reason = "finding-2"
				}
				ep := decide.EscalationParams{DenialScanner: "test", DenialReason: reason, PolicyHash: "test-policy"}
				want, wantFrom, wantTo := false, "", ""
				if !session.ClassifiedDenialSignal(sig) || shouldScoreClassifiedDenial(enforced, scope, ep) {
					want, wantFrom, wantTo = enforced.RecordScopedSignal(scope, sig, cfg.EscalationThreshold)
				}
				got, from, to := observed.ObserveWatchOnlySignal(scope, sig, cfg, ep)
				if got != want || from != wantFrom || to != wantTo {
					t.Fatalf("signal %d: got %t/%s/%s want %t/%s/%s", i, got, from, to, want, wantFrom, wantTo)
				}
			}
			if observed.ThreatScore() != 0 || observed.EscalationLevel() != 0 || len(observed.scopes) != 0 || len(observed.classifiedDenials) != 0 {
				t.Fatal("watch scoring changed enforcing state")
			}
			if observed.AirlockTier() != initialAirlock {
				t.Fatal("watch scoring entered airlock")
			}
			if got, want := observed.watchAdaptive.ScopedThreatScore(scope), enforced.ScopedThreatScore(scope); got != want {
				t.Fatalf("observation score=%v, existing scorer=%v", got, want)
			}
		})
	}
}

func TestWatchOnlyAdaptiveLifecycle(t *testing.T) {
	cfg := config.Defaults()
	adaptive := watchAdaptiveConfig()
	manager := NewSessionManager(&cfg.SessionProfiling, adaptive, nil)
	defer manager.Close()
	state := manager.GetOrCreate("watch-test")
	if state == nil {
		t.Fatal("session unavailable")
	}
	signal := func() {
		state.ObserveWatchOnlySignal("api.vendor.example", session.SignalBlock, adaptive, decide.EscalationParams{})
	}
	signal()
	first := state.watchAdaptive
	same := *adaptive
	manager.UpdateConfig(&cfg.SessionProfiling, &same, &cfg.Airlock)
	if state.watchAdaptive != first {
		t.Fatal("unchanged reload discarded observation")
	}
	changed := same
	changed.EscalationThreshold *= 2
	manager.UpdateConfig(&cfg.SessionProfiling, &changed, &cfg.Airlock)
	if state.watchAdaptive != nil {
		t.Fatal("changed policy retained stale observation")
	}
	signal()
	manager.ResetWatchOnlyAdaptive()
	if state.watchAdaptive != nil {
		t.Fatal("mode transition retained observation")
	}
	signal()
	_, _ = state.Reset(false)
	if state.watchAdaptive != nil {
		t.Fatal("admin reset retained observation")
	}
	signal()
	disabled := *adaptive
	disabled.Enabled = false
	manager.UpdateConfig(&cfg.SessionProfiling, &disabled, &cfg.Airlock)
	if state.watchAdaptive != nil {
		t.Fatal("disabled adaptive retained observation")
	}
	if changed, _, _ := state.ObserveWatchOnlySignal("", session.SignalBlock, &disabled, decide.EscalationParams{}); changed || state.watchAdaptive != nil {
		t.Fatal("disabled adaptive allocated or escalated observation")
	}
	manager.Delete("watch-test")
	replacement := manager.GetOrCreate("watch-test")
	if replacement == state || replacement.watchAdaptive != nil {
		t.Fatal("deleted session leaked observation history")
	}
}

func TestWatchOnlyAdaptiveRecoveryAndNeutralSignals(t *testing.T) {
	cfg := watchAdaptiveConfig()
	state := &SessionState{}
	scope := "api.vendor.example"
	for range 4 {
		if changed, _, _ := state.ObserveWatchOnlySignal(scope, session.SignalWarning, cfg, decide.EscalationParams{}); changed {
			t.Fatal("warning contributed escalation")
		}
	}
	if len(state.watchAdaptive.scopes) != 0 {
		t.Fatal("warnings allocated scope lanes")
	}
	state.ObserveWatchOnlySignal(scope, session.SignalBlock, cfg, decide.EscalationParams{})
	shadow := state.watchAdaptive
	before := shadow.ScopedThreatScore(scope)
	state.ObserveWatchOnlyClean(scope, cfg)
	want := before - cfg.DecayPerCleanRequest
	if want < 0 {
		want = 0
	}
	if got := shadow.ScopedThreatScore(scope); got != want {
		t.Fatalf("clean decay=%v want %v", got, want)
	}
	shadow.mu.Lock()
	shadow.lastSignal = time.Now().Add(-2 * adaptiveLevelDuration(cfg))
	shadow.scopes[scope].lastSignal = shadow.lastSignal
	shadow.mu.Unlock()
	state.ObserveWatchOnlySignal(scope, session.SignalNearMiss, cfg, decide.EscalationParams{})
	if got := shadow.ScopedThreatScore(scope); got != session.SignalPoints[session.SignalNearMiss] {
		t.Fatalf("quiet-period residual failed to expire: %v", got)
	}
	if state.ThreatScore() != 0 || state.EscalationLevel() != 0 {
		t.Fatal("simulation recovery changed enforcement")
	}
}

func TestWatchOnlyAdaptiveBoundedAndConcurrent(t *testing.T) {
	cfg := watchAdaptiveConfig()
	state := &SessionState{}
	var wg sync.WaitGroup
	for i := range maxAdaptiveScopes + 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state.ObserveWatchOnlySignal(fmt.Sprintf("host-%d.vendor.example", i), session.SignalBlock, cfg, decide.EscalationParams{})
		}()
	}
	wg.Wait()
	if got := len(state.watchAdaptive.scopes); got != maxAdaptiveScopes {
		t.Fatalf("scope count=%d want %d", got, maxAdaptiveScopes)
	}
	if state.ThreatScore() != 0 || state.EscalationLevel() != 0 || len(state.scopes) != 0 {
		t.Fatal("concurrent simulation affected enforcement")
	}
}

// A preexisting enforced level must survive watch-only reset unchanged.
func TestWatchOnlyAdaptiveResetPreservesEnforcedState(t *testing.T) {
	cfg := watchAdaptiveConfig()
	state := &SessionState{}
	state.RecordScopedSignal("api.vendor.example", session.SignalBlock, session.SignalPoints[session.SignalBlock])
	before := state.ScopedSnapshots()
	state.ObserveWatchOnlySignal("api.vendor.example", session.SignalBlock, cfg, decide.EscalationParams{})
	state.ResetWatchOnlyAdaptive()
	if !reflect.DeepEqual(before, state.ScopedSnapshots()) {
		t.Fatal("watch reset changed an enforced lane")
	}
}
