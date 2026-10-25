// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestAutoAnchorLivePrefixAppends(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "prefix", true: "strict_control"}[strict], func(t *testing.T) {
			rig := newAutoAnchorTestRig(t)
			rig.cfg.FlightRecorder.Anchor.ReceiptThreshold = uint64Pointer(1)
			emitAutoAnchorReceipt(t, rig.emitter, "https://api.vendor.example/start")
			before, err := rig.emitter.TailObservation()
			if err != nil {
				t.Fatal(err)
			}
			walk := rig.monitor.walkFn
			rig.monitor.walkFn = func(dir, session string, prefix recorder.SessionHistoryPrefix, consume func(receipt.Receipt) error) error {
				appendOnce := true
				callback := func(r receipt.Receipt) error {
					if appendOnce {
						appendOnce = false
						emitAutoAnchorReceipt(t, rig.emitter, "https://api.vendor.example/concurrent")
					}
					return consume(r)
				}
				if strict {
					return receipt.WalkReceiptsFromSessionDir(dir, session, callback)
				}
				return walk(dir, session, prefix, callback)
			}
			rig.monitor.runPass()
			if strict {
				if !strings.Contains(rig.logs.String(), "evidence changed during read") {
					t.Fatalf("control did not reproduce: %s", rig.logs)
				}
				assertAutoAnchorStats(t, rig.metrics, 1, 0, 1, "evidence changed")
				return
			}
			entries, err := anchorpkg.ReadLocalLog(rig.cfg.FlightRecorder.Anchor.LocalLog)
			if err != nil || len(entries) != 1 {
				t.Fatalf("entries=%v err=%v logs=%s", entries, err, rig.logs)
			}
			if c := entries[0].Checkpoint; c.FinalSeq != before.PersistedSeq || c.RootHash != before.PersistedHash {
				t.Fatalf("wrong observation: %+v", c)
			}
			rig.monitor.walkFn = walk
			// Seed a fresh monitor from the real bundle while the writer appends.
			restarted := newAutoAnchorMonitor(rig.recorder, rig.metrics, func() *receipt.Emitter { return rig.emitter }, func() *config.Config { return rig.cfg }, rig.logs)
			seedAppended := false
			restarted.walkFn = func(dir, session string, prefix recorder.SessionHistoryPrefix, consume func(receipt.Receipt) error) error {
				return walk(dir, session, prefix, func(r receipt.Receipt) error {
					if !seedAppended {
						seedAppended = true
						emitAutoAnchorReceipt(t, rig.emitter, "https://api.vendor.example/seed")
					}
					return consume(r)
				})
			}
			snapshot, _ := rig.emitter.HealthSnapshot()
			if err := restarted.seed(time.Now().UTC(), snapshot, rig.emitter); err != nil {
				t.Fatal(err)
			}
			if !seedAppended {
				t.Fatal("seed did not read real history")
			}
			rig.monitor.runPass()
			entries, err = anchorpkg.ReadLocalLog(rig.cfg.FlightRecorder.Anchor.LocalLog)
			if err != nil || len(entries) != 2 {
				t.Fatalf("next pass entries=%v err=%v", entries, err)
			}
			if entries[1].Checkpoint.FinalSeq <= before.PersistedSeq {
				t.Fatal("next pass did not advance")
			}
			if rig.logs.Len() != 0 {
				t.Fatalf("logs=%s", rig.logs)
			}
		})
	}
}

func TestAutoAnchorLivePrefixWritePending(t *testing.T) {
	rig := newAutoAnchorTestRig(t)
	// A session without a recorder write position is pending, never a failed
	// integrity check or a successful checkpoint.
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rig.recorder, PrivKey: rig.priv, ConfigHash: "pending", Principal: "tester", Actor: "runtime-test", Session: "unwritten"})
	rig.monitor.sessionID = emitter.Session()
	_, _, err := rig.monitor.buildCheckpoint(emitter, 0)
	if !errors.Is(err, errAutoAnchorWritePending) {
		t.Fatalf("expected pending write, got %v", err)
	}
	rig.monitor.fail(err)
	if rig.logs.Len() != 0 {
		t.Fatalf("pending write logged a failure: %s", rig.logs)
	}
	rig.monitor.fail(errors.New("unrelated integrity failure"))
	if !strings.Contains(rig.logs.String(), "unrelated integrity failure") {
		t.Fatal("unrelated refusal was swallowed")
	}
}

func TestAutoAnchorLivePrefixRejectsTruncatedHead(t *testing.T) {
	rig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, rig.emitter, "https://api.vendor.example/first")
	emitAutoAnchorReceipt(t, rig.emitter, "https://api.vendor.example/last")
	obs, err := rig.emitter.TailObservation()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the emitter head while its writer-observed file size is shortened.
	p := filepath.Join(rig.recorder.Dir(), obs.WriteFile)
	raw, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndexByte(strings.TrimSuffix(string(raw), "\n"), '\n') + 1
	if err := os.Truncate(p, int64(end)); err != nil {
		t.Fatal(err)
	}
	_, _, err = rig.monitor.buildCheckpoint(rig.emitter, 0)
	if err == nil || !strings.Contains(err.Error(), "writer-observed head") {
		t.Fatalf("truncated head accepted or wrong refusal: %v", err)
	}
}

func TestAutoAnchorLivePrefixUnconfirmedHead(t *testing.T) {
	rig := newAutoAnchorTestRig(t)
	emitAutoAnchorReceipt(t, rig.emitter, "https://api.vendor.example/first")
	rig.recorder.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	err := rig.emitter.EmitDurable(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/failed"})
	if err == nil {
		t.Fatal("sync failure not reproduced")
	}
	_, _, err = rig.monitor.buildCheckpoint(rig.emitter, 0)
	if err == nil || !strings.Contains(err.Error(), "unconfirmed") {
		t.Fatalf("err=%v", err)
	}
}
