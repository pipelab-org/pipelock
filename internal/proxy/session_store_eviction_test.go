// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"runtime"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSessionStoreEvictionProtectsRetainedRecorder(t *testing.T) {
	for name, protect := range capacityProtectionCases() {
		for _, retainedOnly := range []bool{false, true} {
			label := "/stored"
			if retainedOnly {
				label = "/retained-only"
			}
			t.Run(name+label, func(t *testing.T) {
				sm := NewSessionManager(testSessionConfig(), capacityAdaptiveConfig(), nil)
				t.Cleanup(sm.Close)
				rec := sm.GetOrCreate("listener")
				if retainedOnly {
					// Model a clean shared entry evicted before the listener's next
					// response taints its retained recorder.
					sm.Delete("listener")
				}
				rec.mu.Lock()
				protect(rec)
				rec.mu.Unlock()
				evictor := sm.AsStore().(session.CapacityEvictor)
				if evictor.EvictIfUnprotected("listener", rec) {
					t.Fatal("pressure eviction discarded enforcement")
				}
				if !retainedOnly && sm.SessionByKey("listener") != rec {
					t.Fatal("refused eviction changed the store")
				}
			})
		}
	}
}

func TestSessionStoreEvictionIdentityAndRecovery(t *testing.T) {
	for _, kind := range []string{"clean", "retained-clean", "nil", "typed-nil", "foreign-recorder", "wrong-key", "replacement", "adaptive-disabled"} {
		t.Run(kind, func(t *testing.T) {
			m := metrics.New()
			sm := NewSessionManager(testSessionConfig(), capacityAdaptiveConfig(), m)
			t.Cleanup(sm.Close)
			rec := sm.GetOrCreate("listener")
			var target session.Recorder = rec
			want := false
			switch kind {
			case "clean":
				want = true
			case "retained-clean":
				sm.Delete("listener")
				want = true
			case "nil":
				target = nil
			case "typed-nil":
				target = (*SessionState)(nil)
			case "foreign-recorder":
				target = struct{ session.Recorder }{rec}
			case "wrong-key":
				sm.Delete("listener")
				target = sm.GetOrCreate("other")
			case "replacement":
				sm.Delete("listener")
				sm.GetOrCreate("listener")
			case "adaptive-disabled":
				rec.mu.Lock()
				rec.escalationLevel = 1
				rec.mu.Unlock()
				sm.UpdateConfig(testSessionConfig(), nil, nil)
				want = true
			}
			before := sm.SessionByKey("listener")
			if got := sm.AsStore().(session.CapacityEvictor).EvictIfUnprotected("listener", target); got != want {
				t.Fatalf("eviction=%t, want %t", got, want)
			}
			if want && sm.SessionByKey("listener") != nil {
				t.Fatal("clean recorder retained")
			}
			if !want && sm.SessionByKey("listener") != before {
				t.Fatal("rejected eviction removed another recorder")
			}
		})
	}
}

func TestSessionStoreEvictionSerializesProtection(t *testing.T) {
	for name, protect := range capacityProtectionCases() {
		t.Run(name, func(t *testing.T) {
			sm := NewSessionManager(testSessionConfig(), capacityAdaptiveConfig(), nil)
			t.Cleanup(sm.Close)
			rec := sm.GetOrCreate("listener")
			rec.mu.Lock()
			result := make(chan bool, 1)
			go func() { result <- sm.AsStore().(session.CapacityEvictor).EvictIfUnprotected("listener", rec) }()

			// Wait until eviction owns the map lock and is blocked on the recorder.
			// A concurrent policy observation must become visible before removal.
			deadline := time.Now().Add(5 * time.Second)
			for {
				select {
				case removed := <-result:
					rec.mu.Unlock()
					t.Fatalf("eviction returned while recorder was locked: %t", removed)
				default:
				}
				if !sm.mu.TryLock() {
					break
				}
				sm.mu.Unlock()
				if time.Now().After(deadline) {
					rec.mu.Unlock()
					t.Fatal("eviction did not acquire the map lock")
				}
				runtime.Gosched()
			}
			protect(rec)
			rec.mu.Unlock()
			select {
			case removed := <-result:
				if removed || sm.SessionByKey("listener") != rec {
					t.Fatal("concurrent policy observation was discarded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("eviction did not finish after recorder unlock")
			}
		})
	}
}
