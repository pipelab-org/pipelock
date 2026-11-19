// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func writerTestHold(id string) Action {
	hold := writerTestIntent(id)
	hold.Attempt = nil
	hold.Hold = &Hold{
		ID: id + "-approval", Parent: "prior-approval", Policy: "operator",
	}
	hold.Phase, hold.EffectBoundary, hold.Verdict = phaseHold, approvalBoundary, "defer"
	hold.Session = &Session{ID: "example-work", TaskLabel: "read"}
	hold.Caller = Caller{Authn: "mcp_door_verified", Resource: "api.vendor.example", Issuer: "issuer.vendor.example", Subject: "person", ClientID: "client"}
	return hold
}

func TestStreamWriterRecoversHoldsFromVerifiedHistory(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	policy := CapturePolicy(Digest([]byte("request config")))
	for _, id := range []string{"pending", "allow", "block", "ask", "intent", "outcome"} {
		held := writerTestHold(id)
		if err := w.WriteAction(t.Context(), held, policy); err != nil {
			t.Fatal(err)
		}
		if id == "pending" {
			continue
		}
		resolution := blockingHoldResolution(held, "operator", relationAfter, false)
		resolution.Verdict = id
		switch id {
		case "ask":
			resolution.Ask = &Ask{Channel: "approval_api", Observed: true}
		case "intent", "outcome":
			resolution.Verdict = verdictAllow
		}
		if err := w.WriteAction(t.Context(), resolution, policy); err != nil {
			t.Fatal(err)
		}
		if id != "intent" && id != "outcome" {
			continue
		}
		intent := writerTestIntent(id)
		if err := w.WriteAction(t.Context(), intent, policy); err != nil {
			t.Fatal(err)
		}
		if id == "outcome" {
			intent.Phase, intent.EffectRelation, intent.OutcomeClass = phaseOutcome, relationAfter, "completed"
			if err := w.WriteAction(t.Context(), intent, policy); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}

	recovery := requireWriter(t, opts, localWriterStorage())
	got := readRecoveryActions(t, opts.Dir, recovery.active.id)
	pending := writerTestHold("pending")
	pending.Policy = policy.ActionPolicy()
	allowed := writerTestHold("allow")
	allowed.Policy = policy.ActionPolicy()
	want := []Action{
		blockingHoldResolution(allowed, "restart_recovery", relationAfter, true),
		blockingHoldResolution(pending, "restart_recovery", "unknown", false),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recoveries = %+v, want %+v", got, want)
	}
	if err := recovery.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	second := requireWriter(t, opts, localWriterStorage())
	if got := readRecoveryActions(t, opts.Dir, second.active.id); len(got) != 0 {
		t.Fatalf("recovery was repeated: %+v", got)
	}
	if err := second.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	for state, want := range map[string]int64{"blocked": 3, "stepped_up": 1, "outcome_unknown": 1, "completed": 1} {
		if got := writerTestCount(t, result, state); got != want {
			t.Errorf("%s = %d, want %d", state, got, want)
		}
	}
}

func TestStreamWriterRetriesRecoveryAfterWriteError(t *testing.T) {
	for _, tc := range []struct {
		name          string
		failSuccessor bool
	}{
		{name: "successor confirms repair"},
		{name: "successor publication fails", failSuccessor: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			opts.Heartbeat = 0
			w, err := openStreamWriter(t.Context(), opts, localWriterStorage())
			if err != nil {
				t.Fatal(err)
			}
			hold := writerTestHold("pending")
			policy := CapturePolicy(Digest([]byte("request config")))
			writeErr := w.WriteAction(t.Context(), hold, policy)
			if err := errors.Join(writeErr, abandonWriterReplay(w)); err != nil {
				t.Fatal(err)
			}

			// Re-flush the predecessor, publish the startup stream, then
			// fail the recovery append before it writes any bytes.
			fault := writerReplayFault{step: writerReplayStep{FaultAt: 7}}
			storage := fault.storage(opts.Dir)
			link := storage.link
			storage.link = func(oldPath, newPath string) error {
				if tc.failSuccessor && len(fault.calls) > fault.step.FaultAt {
					return errWriterReplay
				}
				return link(oldPath, newPath)
			}
			recovered, err := openStreamWriter(t.Context(), opts, storage)
			t.Cleanup(func() { _ = abandonWriterReplay(recovered) })
			if tc.failSuccessor {
				if recovered != nil || !errors.Is(err, errWriterReplay) ||
					!strings.Contains(err.Error(), "publish receipt stream opening") {
					t.Fatalf("expected startup refusal after successor publication failure, got %v", err)
				}
				// A failed startup must release the lock for another start.
				next := requireWriter(t, opts, localWriterStorage())
				if got := readRecoveryActions(t, opts.Dir, next.active.id); len(got) != 1 {
					t.Fatalf("pending hold was lost: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			hold.Policy = policy.ActionPolicy()
			want := []Action{blockingHoldResolution(hold, "restart_recovery", "unknown", false)}
			if got := readRecoveryActions(t, opts.Dir, recovered.active.id); !reflect.DeepEqual(got, want) {
				t.Fatalf("recoveries = %+v, want %+v", got, want)
			}
			result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			streams := result.Histories[0].Streams
			if len(streams) != 3 {
				t.Fatalf("expected three streams, got %+v", streams)
			}
			for _, stream := range streams {
				if stream.End == "superseded_write_error" && stream.Tip != nil && stream.Tip.Seq == 0 {
					return
				}
			}
			t.Fatalf("missing write-error pin at the failed stream opening: %+v", streams)
		})
	}
}

func readRecoveryActions(t *testing.T, dir, stream string) []Action {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(writerFilename(stream, 0))
	if err != nil {
		t.Fatal(err)
	}
	var out []Action
	for line := range bytes.SplitAfterSeq(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		r, code := parseLine(line, "")
		if code != "" {
			t.Fatal(code)
		}
		if r.Kind == kindAction {
			var action Action
			if err := json.Unmarshal(r.Body, &action); err != nil {
				t.Fatal(err)
			}
			out = append(out, action)
		}
	}
	return out
}

func TestStreamWriterRefusesUninterpretedEffectiveActions(t *testing.T) {
	for _, tc := range []struct {
		finding string
		version int64
		verdict string
	}{
		{finding: codeActionUninterpreted, version: 1, verdict: "future"},
		{finding: codeDecisionsNotAppraised, version: 2, verdict: "defer"},
	} {
		t.Run(tc.finding, func(t *testing.T) {
			dir := t.TempDir()
			first := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
			held := writerTestHold("opaque")
			held.Policy = PolicySnapshot{}.ActionPolicy()
			held.Verdict = tc.verdict
			first.addVersion(kindAction, tc.version, held)
			first.close()
			first.write(dir)
			opts := writerTestOptions(dir)
			opts.SigningKey = first.key
			_, err := OpenStreamWriter(t.Context(), opts)
			if err == nil || !strings.Contains(err.Error(), tc.finding) ||
				!strings.Contains(err.Error(), fmt.Sprintf("action body version %d", tc.version)) {
				t.Fatalf("wanted compatibility refusal, got %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatal("refused startup published a successor")
			}
		})
	}
}

func TestStreamWriterIgnoresUninterpretedActionInFailedTail(t *testing.T) {
	dir := t.TempDir()
	first := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	held := writerTestHold("pending")
	held.Policy = PolicySnapshot{}.ActionPolicy()
	first.add(kindAction, held)
	pin := &Previous{Stream: first.id, Ended: endedWriteError, Seq: 1, Record: first.tip}
	first.addVersion(kindAction, 2, writerTestHold("opaque"))
	first.write(dir)
	second := signedStream(t, 2, pin, nil)
	second.close()
	second.write(dir)
	opts := writerTestOptions(dir)
	opts.SigningKey = first.key
	w := requireWriter(t, opts, localWriterStorage())
	got := readRecoveryActions(t, dir, w.active.id)
	if len(got) != 1 || got[0].ActionID != held.ActionID || got[0].EffectRelation != "unknown" {
		t.Fatalf("confirmed hold did not recover: %+v", got)
	}
}
