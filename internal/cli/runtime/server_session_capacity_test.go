// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestServerSessionEnforcementCapacitySurvivesReload(t *testing.T) {
	const body = "mode: balanced\nsession_profiling:\n  enabled: true\n  max_sessions: 1\nadaptive_enforcement:\n  enabled: true\n"
	path := writeServerTestConfig(t, body)
	s, err := NewServer(ServerOpts{ConfigFile: path, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	sm := s.proxy.SessionMgrPtr().Load()
	if sm == nil {
		t.Fatal("startup omitted session store")
	}
	victim := sm.GetOrCreate("192.0.2.1")
	victim.ObserveRisk(session.RiskObservation{Source: session.TaintSourceRef{Level: session.TaintExternalHostile}})
	for _, next := range []string{body, body + "explain_blocks: true\n"} {
		writeReloadCandidate(t, s, next)
		outcome := s.ReloadFile()
		if outcome.Verdict != proxy.ReloadAccepted && outcome.Verdict != proxy.ReloadUnchanged {
			t.Fatalf("reload: %+v", outcome)
		}
		current := s.proxy.SessionMgrPtr().Load()
		if current.SessionByKey("192.0.2.1") != victim || current.AsStore().GetOrCreate("192.0.2.2") != nil || current.Len() != 1 {
			t.Fatal("reload discarded protected state or bypassed the session cap")
		}
	}
	if _, found, err := sm.ResetSessionIfResettable("192.0.2.1"); err != nil || !found {
		t.Fatalf("reset: found=%t err=%v", found, err)
	}
	if sm.GetOrCreate("192.0.2.2") != nil {
		t.Fatal("adaptive reset erased sticky taint")
	}
	if _, _, _, found, err := sm.BeginNewTask("192.0.2.1", "recovery"); err != nil || !found {
		t.Fatalf("new task: found=%t err=%v", found, err)
	}
	if sm.GetOrCreate("192.0.2.2") == nil || sm.Len() != 1 {
		t.Fatal("new task did not restore admission")
	}
}
