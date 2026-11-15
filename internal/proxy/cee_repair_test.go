// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestClassifiedDenialRecoveryEpisodes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold float64
	}{{"timer", 1}, {"residual", 100}} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SessionState{}
			scope, other := adaptiveScopeForHost("api.vendor.example"), adaptiveScopeForHost("other.vendor.example")
			note := func(scope string) bool { return s.NoteClassifiedDenial(scope, "injection", "same finding", "policy") }
			if !note(scope) || note(scope) || !note(other) {
				t.Fatal("initial deduplication failed")
			}
			s.RecordScopedSignal(scope, session.SignalBlock, tc.threshold)
			ageAdaptiveResidual(s, 2*time.Hour)
			s.TryAutoRecoverScopes(time.Hour, nil)
			if !note(scope) {
				t.Fatal("same finding did not score after lane recovery")
			}
			if note(other) {
				t.Fatal("recovery cleared unrelated destination")
			}
		})
	}
}

func TestAdaptiveOverflowPrintableSnapshot(t *testing.T) {
	if normalizeAdaptiveScope(adaptiveOverflowScope) != adaptiveOverflowScope || strings.HasPrefix(adaptiveOverflowScope, adaptiveScopeForHost("example")[:len("destination:")]) {
		t.Fatal("overflow label collides with destination namespace or changes on normalization")
	}
	s := &SessionState{}
	for i := 0; i < maxAdaptiveScopes+1; i++ {
		s.RecordScopedSignal(adaptiveScopeForHost(fmt.Sprintf("host-%d.vendor.example", i)), session.SignalBlock, 1000000)
	}
	for _, snap := range s.ScopedSnapshots() {
		if snap.Scope == adaptiveOverflowScope {
			if strings.ContainsRune(snap.Scope, '\x00') {
				t.Fatalf("overflow snapshot scope contains NUL: %q", snap.Scope)
			}
			return
		}
	}
	t.Fatal("overflow snapshot missing")
}

func TestAdaptiveOverflowAdmissionCancel(t *testing.T) {
	s := &SessionState{airlock: *NewAirlockState()}
	for i := 0; i < maxAdaptiveScopes; i++ {
		s.AirlockForScope(adaptiveScopeForHost(fmt.Sprintf("host-%d.vendor.example", i)))
	}
	scope := adaptiveScopeForHost("later.vendor.example")
	cancelled := make(chan struct{})
	s.AirlockForScope(scope).RegisterCancel(func() { close(cancelled) })
	s.RecordScopedSignal(scope, session.SignalBlock, 1)
	_, _, _ = s.AirlockForScope(scope).SetTier(config.AirlockTierDrain)
	select {
	case <-cancelled:
	default:
		t.Fatal("overflow drain did not cancel pre-membership connection")
	}
}

func TestClassifiedDenialInterceptRecovery(t *testing.T) {
	cfg := config.Defaults()
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 1
	cfg.Airlock.Enabled = false
	s := &SessionState{airlock: *NewAirlockState()}
	ic := &InterceptContext{TargetHost: "api.vendor.example", Config: cfg, Recorder: s}
	scope := adaptiveScopeForHost(ic.TargetHost)
	finding := func() { interceptRecordFinding(ic, session.SignalBlock, "injection", "same finding") }
	finding()
	first := s.ScopedThreatScore(scope)
	finding()
	if s.ScopedThreatScore(scope) != first {
		t.Fatal("duplicate intercept finding scored")
	}
	s.RecordScopedCleanWithRecovery(scope, 0, 1, nil)
	if s.ScopedEscalationLevel(scope) != 0 {
		t.Fatal("clean recovery did not reach level zero")
	}
	before := s.ScopedThreatScore(scope)
	finding()
	if s.ScopedThreatScore(scope) <= before {
		t.Fatal("intercept finding did not score after clean recovery")
	}
}

func TestClassifiedDenialGlobalAndOverflowRecovery(t *testing.T) {
	for _, scope := range []string{"", "overflow"} {
		t.Run(scope, func(t *testing.T) {
			s := &SessionState{airlock: *NewAirlockState()}
			target, other := "", adaptiveScopeForHost("other.vendor.example")
			if scope == "overflow" {
				for i := 0; i < maxAdaptiveScopes; i++ {
					s.AirlockForScope(adaptiveScopeForHost(fmt.Sprintf("host-%d.vendor.example", i)))
				}
				target = adaptiveScopeForHost("overflow.vendor.example")
			}
			note := func(v string) bool { return s.NoteClassifiedDenial(v, "injection", "finding", "policy") }
			if !note(target) || !note(other) {
				t.Fatal("initial fingerprints missing")
			}
			s.RecordScopedSignal(target, session.SignalBlock, 1)
			ageAdaptiveResidual(s, 2*time.Hour)
			if scope == "" {
				s.TryAutoRecover(time.Hour, nil)
			} else {
				s.TryAutoRecoverScopes(time.Hour, nil)
			}
			if !note(target) {
				t.Fatal("recovered lane did not clear fingerprint")
			}
			if note(other) {
				t.Fatal("recovery cleared unrelated fingerprint")
			}
		})
	}
}

func TestClassifiedDenialCleanResidualRecovery(t *testing.T) {
	for _, scope := range []string{"", adaptiveScopeForHost("api.vendor.example")} {
		t.Run(scope, func(t *testing.T) {
			s := &SessionState{}
			note := func() bool { return s.NoteClassifiedDenial(scope, "injection", "finding", "policy") }
			if !note() {
				t.Fatal("initial finding did not score")
			}
			s.RecordScopedSignal(scope, session.SignalBlock, 100)
			s.RecordScopedClean(scope, 100)
			if !note() {
				t.Fatal("finding did not score after clean residual decay")
			}
		})
	}
}

func TestClassifiedDenialResidualExpiresBeforeRetry(t *testing.T) {
	cfg := config.Defaults()
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.ApplyDefaults()
	sm := NewSessionManager(testSessionConfig(), &cfg.AdaptiveEnforcement, nil)
	defer sm.Close()
	s := sm.GetOrCreate("expiry-retry")
	scope := adaptiveScopeForHost("api.vendor.example")
	note := func() bool { return s.NoteClassifiedDenial(scope, "injection", "finding", "policy") }
	if !note() {
		t.Fatal("initial finding did not score")
	}
	s.RecordScopedSignal(scope, session.SignalBlock, 100)
	ageAdaptiveResidual(s, 2*adaptiveLevelDuration(&cfg.AdaptiveEnforcement))
	if !note() {
		t.Fatal("expired residual suppressed the next finding")
	}
}

func TestClassifiedDenialOverflowExpiryBeforeNewMember(t *testing.T) {
	cfg := config.Defaults()
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.ApplyDefaults()
	sm := NewSessionManager(testSessionConfig(), &cfg.AdaptiveEnforcement, nil)
	defer sm.Close()
	s := sm.GetOrCreate("overflow-expiry")
	for i := 0; i < maxAdaptiveScopes; i++ {
		s.AirlockForScope(adaptiveScopeForHost(fmt.Sprintf("host-%d.vendor.example", i)))
	}
	s.RecordScopedSignal(adaptiveScopeForHost("first.vendor.example"), session.SignalBlock, 100)
	ageAdaptiveResidual(s, 2*adaptiveLevelDuration(&cfg.AdaptiveEnforcement))
	scope := adaptiveScopeForHost("next.vendor.example")
	note := func() bool { return s.NoteClassifiedDenial(scope, "injection", "finding", "policy") }
	if !note() {
		t.Fatal("initial finding did not score")
	}
	s.RecordScopedSignal(scope, session.SignalBlock, 100)
	if note() {
		t.Fatal("overflow expiry forgot the new member's finding")
	}
}

func TestResponseDenialReasonIsStableAcrossMatchCountsAndOrder(t *testing.T) {
	base := responseDenialReason([]string{"Prompt Injection", "System Override"})
	for _, names := range [][]string{
		{"Prompt Injection", "Prompt Injection", "System Override"},
		{"System Override", "Prompt Injection"},
		{"System Override", "Prompt Injection", "System Override", "Prompt Injection"},
	} {
		if got := responseDenialReason(names); got != base {
			t.Fatalf("responseDenialReason(%q) = %q, want %q", names, got, base)
		}
	}
	if got := responseDenialReason([]string{"Prompt Injection"}); got == base {
		t.Fatalf("a different pattern set must give a different fingerprint, got %q for both", got)
	}
	names := []string{"System Override", "Prompt Injection", "System Override"}
	_ = responseDenialReason(names)
	if names[0] != "System Override" || len(names) != 3 {
		t.Fatalf("responseDenialReason modified its input: %q", names)
	}
}
