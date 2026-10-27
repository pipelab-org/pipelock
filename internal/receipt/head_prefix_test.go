// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestHeadTrustedVerifierObservedHead(t *testing.T) {
	_, priv := generateTestKey(t)
	record := validActionRecord()
	record.ChainPrevHash = GenesisHash
	r, err := Sign(record, priv)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := ReceiptHash(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"match", "sequence", "hash", "empty", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			v, err := NewHeadTrustedVerifier(r.SignerKey, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = v.Close() })
			if mode != "empty" {
				copyReceipt := r
				if mode == "invalid" {
					copyReceipt.Signature = "invalid"
				}
				_ = v.Add(copyReceipt)
			}
			seq, wantHash := r.ActionRecord.ChainSeq, hash
			if mode == "sequence" {
				seq++
			}
			if mode == "hash" {
				wantHash = GenesisHash
			}
			full, _, err := v.FinishAtHead(seq, wantHash)
			if mode == "match" {
				if err != nil || !full.Valid {
					t.Fatalf("full=%+v err=%v", full, err)
				}
			} else if err == nil || full.Valid {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
}

func TestConfirmedTailObservationWaitsForDurability(t *testing.T) {
	e, rec := newDeferredTestEmitter(t, nil)
	entered := make(chan struct{})
	var once sync.Once
	release := gateSync(t, rec, func() { once.Do(func() { close(entered) }) })
	emitted := make(chan error, 1)
	go func() { emitted <- e.EmitDurable(deferredTestOpts(testTarget)) }()
	waitSignal(t, entered, "pending durable sync")
	type result struct {
		obs TailObservation
		err error
	}
	observed := make(chan result, 1)
	go func() {
		obs, err := e.ConfirmedTailObservation()
		observed <- result{obs, err}
	}()
	// A waiting exclusive observation blocks new gate readers. This detects
	// actual lock contention without relying on a scheduling delay.
	testwait.For(t, 10*time.Second, func() bool {
		select {
		case got := <-observed:
			t.Fatalf("observation returned before sync: %+v", got)
		default:
		}
		if e.emissionGate.TryRLock() {
			e.emissionGate.RUnlock()
			return false
		}
		return true
	}, "observation did not wait on the emission gate")
	release()
	if err := <-emitted; err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-observed:
		if got.err != nil || got.obs.Unconfirmed || !got.obs.WriteKnown || got.obs.PersistedHash != got.obs.PrevHash {
			t.Fatalf("obs=%+v err=%v", got.obs, got.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("observation blocked after confirmation")
	}
}

func TestConfirmedTailObservationSyncFailure(t *testing.T) {
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, t.TempDir(), priv)
	t.Cleanup(func() { _ = rec.Close() })
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	emit := func() error {
		return e.EmitDurable(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Target: testTarget, Transport: testTransport})
	}
	if err := emit(); err != nil {
		t.Fatal(err)
	}
	obs, err := e.ConfirmedTailObservation()
	if err != nil || obs.Unconfirmed || !obs.WriteKnown || obs.PersistedHash != obs.PrevHash {
		t.Fatalf("obs=%+v err=%v", obs, err)
	}
	rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	if err := emit(); err == nil {
		t.Fatal("expected failed sync")
	}
	obs, err = e.ConfirmedTailObservation()
	if err != nil || !obs.Unconfirmed {
		t.Fatalf("obs=%+v err=%v", obs, err)
	}
	if _, err := (*Emitter)(nil).ConfirmedTailObservation(); err == nil {
		t.Fatal("nil emitter accepted")
	}
}
