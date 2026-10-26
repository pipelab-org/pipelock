// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func capacityProtectionCases() map[string]func(*SessionState) {
	return map[string]func(*SessionState){
		"global level":     func(s *SessionState) { s.escalationLevel = 1 },
		"scoped level":     func(s *SessionState) { s.getOrCreateScopeLocked("vendor.example").escalationLevel = 1 },
		"global block all": func(s *SessionState) { s.atBlockAll = true },
		"scoped block all": func(s *SessionState) { s.getOrCreateScopeLocked("vendor.example").atBlockAll = true },
		"untrusted taint": func(s *SessionState) {
			s.risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{Level: session.TaintExternalUntrusted}})
		},
		"hostile taint": func(s *SessionState) {
			s.risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{Level: session.TaintExternalHostile}})
		},
		// Enforcement reads Level, even if a diagnostic flag is absent.
		"level without flag": func(s *SessionState) { s.risk.Level = session.TaintExternalUntrusted },
		"global airlock":     func(s *SessionState) { _, _, _ = s.airlock.SetTier(config.AirlockTierSoft) },
		"scoped airlock": func(s *SessionState) {
			_, _, _ = s.getOrCreateScopeLocked("vendor.example").airlock.SetTier(config.AirlockTierHard)
		},
	}
}

func TestSessionCapacityProtectsEnforcement(t *testing.T) {
	for name, protect := range capacityProtectionCases() {
		t.Run(name, func(t *testing.T) {
			cfg := testSessionConfig()
			cfg.MaxSessions = 2
			sm := NewSessionManager(cfg, nil, nil)
			t.Cleanup(sm.Close)
			victim := sm.GetOrCreate("victim")
			victim.mu.Lock()
			protect(victim)
			victim.lastActivity = time.Now().Add(-time.Minute)
			victim.mu.Unlock()
			sm.GetOrCreate("clean")
			if sm.GetOrCreate("new") == nil || sm.SessionByKey("clean") != nil || sm.SessionByKey("victim") != victim {
				t.Fatal("mixed capacity discarded enforcement instead of the clean session")
			}
			other := sm.SessionByKey("new")
			other.mu.Lock()
			protect(other)
			other.mu.Unlock()
			for i := range 10 {
				if sm.AsStore().GetOrCreate(fmt.Sprintf("flood-%d", i)) != nil || sm.Len() != cfg.MaxSessions {
					t.Fatal("protected-only capacity admitted a key, returned a typed nil, or exceeded the bound")
				}
			}
			tainted := victim.RiskSnapshot().HasPolicyTaint()
			if _, found := sm.ResetSession("victim"); !found {
				t.Fatal("operator reset lost the protected session")
			}
			if tainted {
				if sm.GetOrCreate("still-tainted") != nil {
					t.Fatal("adaptive reset cleared sticky taint")
				}
				victim.BeginNewTask("recovery")
			}
			if sm.GetOrCreate("after-reset") == nil || sm.SessionByKey("new") != other || sm.Len() != cfg.MaxSessions {
				t.Fatal("operator reset did not restore bounded admission")
			}
		})
	}
}

func TestSessionCapacityIdleBoundary(t *testing.T) {
	for name, protect := range capacityProtectionCases() {
		t.Run(name, func(t *testing.T) {
			cfg := testSessionConfig()
			cfg.MaxSessions = 1
			sm := NewSessionManager(cfg, nil, nil)
			t.Cleanup(sm.Close)
			victim := sm.GetOrCreate("victim")
			victim.mu.Lock()
			protect(victim)
			victim.lastActivity = time.Now().Add(-2 * time.Duration(cfg.SessionTTLMinutes) * time.Minute)
			quarantined := victim.hasActiveAirlockLocked()
			victim.mu.Unlock()
			sm.cleanup()
			if retained := sm.SessionByKey("victim") != nil; retained != quarantined {
				t.Fatalf("idle retention = %t, quarantine = %t", retained, quarantined)
			}
		})
	}
}

func TestSessionCapacityRecoveryAndCleanTaint(t *testing.T) {
	for _, scope := range []string{"", "vendor.example"} {
		t.Run(scope, func(t *testing.T) {
			cfg := testSessionConfig()
			cfg.MaxSessions = 1
			sm := NewSessionManager(cfg, nil, nil)
			t.Cleanup(sm.Close)
			s := sm.GetOrCreate("victim")
			s.mu.Lock()
			if scope == "" {
				s.escalationLevel = 1
				s.lastEscalation = time.Now().Add(-time.Hour)
			} else {
				st := s.getOrCreateScopeLocked(scope)
				st.escalationLevel = 1
				st.lastEscalation = time.Now().Add(-time.Hour)
			}
			s.mu.Unlock()
			if sm.GetOrCreate("refused") != nil {
				t.Fatal("escalated session was evicted")
			}
			if scope == "" {
				s.TryAutoRecover(time.Second, nil)
			} else {
				s.TryAutoRecoverScopes(time.Second, nil)
			}
			// Below the matrix threshold, taint does not need capacity protection.
			s.ObserveRisk(session.RiskObservation{Source: session.TaintSourceRef{Level: session.TaintAllowlistedReference}})
			if sm.GetOrCreate("after-recovery") == nil || sm.SessionByKey("victim") != nil {
				t.Fatal("recovered session remained pinned")
			}
		})
	}
}

func TestSessionCapacityConcurrentEnforcement(t *testing.T) {
	cfg := testSessionConfig()
	cfg.MaxSessions = 2
	sm := NewSessionManager(cfg, nil, nil)
	t.Cleanup(sm.Close)
	victim := sm.GetOrCreate("victim")
	victim.ObserveRisk(session.RiskObservation{Source: session.TaintSourceRef{Level: session.TaintExternalHostile}})
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 10 {
				sm.GetOrCreate(fmt.Sprintf("client-%d-%d", i, j))
				if sm.Len() > cfg.MaxSessions || sm.GetOrCreate("victim") != victim {
					t.Error("concurrent admission lost protection or exceeded capacity")
				}
			}
		})
	}
	wg.Wait()
}

func TestSessionCapacityDefaultLimitFlood(t *testing.T) {
	for _, name := range []string{"global level", "untrusted taint"} {
		t.Run(name, func(t *testing.T) {
			// Resolve the shipped default instead of copying its numeric value.
			cfg := config.Defaults().SessionProfiling
			sm := NewSessionManager(&cfg, nil, nil)
			t.Cleanup(sm.Close)
			victim := sm.GetOrCreate("victim")
			victim.mu.Lock()
			capacityProtectionCases()[name](victim)
			victim.lastActivity = time.Now().Add(-time.Minute)
			victim.mu.Unlock()
			for i := range cfg.MaxSessions + 1 {
				if sm.GetOrCreate(fmt.Sprintf("flood-%d", i)) == nil {
					t.Fatal("clean flood admission was refused despite eligible capacity")
				}
			}
			if sm.SessionByKey("victim") != victim || sm.Len() != cfg.MaxSessions {
				t.Fatal("default-capacity flood discarded enforcement or exceeded the bound")
			}
		})
	}
}

func TestSessionToolCallRefreshesIdleActivity(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint(blocked), func(t *testing.T) {
			cfg := testSessionConfig()
			sm := NewSessionManager(cfg, nil, nil)
			t.Cleanup(sm.Close)
			s := sm.GetOrCreate("mcp-stdio-test")
			old := time.Now().Add(-2 * time.Duration(cfg.SessionTTLMinutes) * time.Minute)
			s.mu.Lock()
			s.lastActivity = old
			s.atBlockAll = blocked
			s.mu.Unlock()
			s.RecordToolCall("read_file")
			sm.cleanup()
			if retained := sm.SessionByKey(s.key) != nil; retained == blocked {
				t.Fatalf("retained = %t, block_all = %t", retained, blocked)
			}
			if s.BaselineMetrics().ToolCalls != 1 {
				t.Fatal("tool accounting changed")
			}
		})
	}
}
