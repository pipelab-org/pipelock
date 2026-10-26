// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

type protectedListenerStore struct {
	listenerStateBoundedStore
	protected bool
}

func (s *protectedListenerStore) EvictIfUnprotected(key string, rec session.Recorder) bool {
	if s.protected {
		return false
	}
	return s.listenerStateBoundedStore.EvictIfUnprotected(key, rec)
}

func TestMCPListenerCapacityProtection(t *testing.T) {
	for _, admission := range []string{"legacy", "principal", "setup"} {
		t.Run(admission, func(t *testing.T) {
			for _, kind := range []string{"protected", "clean", "in-flight", "committing", "unsupported-store", "no-store"} {
				t.Run(kind, func(t *testing.T) {
					store := &protectedListenerStore{protected: kind == "protected"}
					var configured session.Store = store
					switch kind {
					case "unsupported-store":
						configured = &capacityTestStore{rec: &mockRecorder{}}
					case "no-store":
						configured = nil
					}
					states := newMCPListenerClientStates(configured)
					victim := states.stateForLegacySession("victim")
					for i := 1; i < maxMCPListenerClients; i++ {
						key := fmt.Sprintf("principal-%d", i)
						state := newMCPListenerClientState("", key)
						state.principal = true
						states.touchLocked(state)
						states.clients[key] = state
						defer state.revoke()
					}
					switch kind {
					case "in-flight":
						victim.inFlight.Add(1)
						defer victim.inFlight.Add(-1)
					case "committing":
						victim.commitMu.Lock()
						defer victim.commitMu.Unlock()
					}
					var admitted *mcpListenerClientState
					switch admission {
					case "legacy":
						admitted = states.stateForLegacySession("replacement")
					case "principal":
						admitted, _ = states.stateForPrincipal(mcpListenerPrincipal{key: "replacement"})
					case "setup":
						candidate, err := states.newSetupState()
						if err != nil {
							t.Fatal(err)
						}
						defer candidate.revoke()
						if states.admitSetup(candidate) {
							admitted = candidate
						}
					}
					wantAdmit := kind == "clean" || kind == "no-store"
					if (admitted != nil) != wantAdmit {
						t.Fatalf("admitted=%t, want %t", admitted != nil, wantAdmit)
					}
					if victim.revoked.Load() != wantAdmit {
						t.Fatalf("victim revoked=%t, want %t", victim.revoked.Load(), wantAdmit)
					}
					if !wantAdmit && states.clients[victim.key] != victim {
						t.Fatal("refused admission removed victim")
					}
					if wantAdmit && configured != nil {
						if _, deleted := store.deleted[victim.key]; !deleted {
							t.Fatal("clean victim recorder was not deleted")
						}
					}
				})
			}
		})
	}
}
