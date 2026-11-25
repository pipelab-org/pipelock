// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
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

func TestStartupHeadRefusesIncompleteHistory(t *testing.T) {
	for _, code := range []string{codeLegacyGroupIncomplete, codeLegacyMembershipUnknown, codeDecisionIndexFull, codeNoEvidence} {
		t.Run(code, func(t *testing.T) {
			result := Result{
				Findings:  []Finding{{Class: incomplete, Code: code}},
				Histories: []HistoryResult{{Streams: []StreamResult{{Stream: "stream", Tip: &Position{}}}}},
			}
			_, _, err := startupHead(result, 0)
			if err == nil || !strings.Contains(err.Error(), code) {
				t.Fatalf("startup refusal for %s = %v", code, err)
			}
		})
	}
}

func TestStartupHeadNamesNewerActionVersionWhenVocabularyIsAlsoUnknown(t *testing.T) {
	result := Result{Findings: []Finding{
		{Class: incomplete, Code: codeActionUninterpreted},
		{Class: incomplete, Code: codeDecisionsNotAppraised},
	}}
	_, _, err := startupHead(result, 2)
	if err == nil || !strings.Contains(err.Error(), "action body version 2 required") {
		t.Fatalf("startup did not report the newer action body version: %v", err)
	}
}

func TestRecoverHoldsRefusesAllowWithoutHold(t *testing.T) {
	dir := t.TempDir()
	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	action := blockingHoldResolution(writerTestHold("missing"), "operator", relationAfter, false)
	action.Verdict = verdictAllow
	action.Policy = PolicySnapshot{}.ActionPolicy()
	stream.add(kindAction, action)
	stream.close()
	stream.write(dir)

	opts := Options{Directory: true, Keys: []ed25519.PublicKey{stream.public()}}
	result, err := verifyPathsInspect(t.Context(), []string{dir}, opts, "", func(v *verification) error {
		// Inspect the staged records directly, bypassing the startup verdict gate.
		verified := v.streams[stream.id]
		if verified == nil {
			t.Fatal("expected a staged stream")
		}
		actions, err := v.recoverHolds(verified.body.Lineage)
		if len(actions) != 0 {
			t.Fatalf("hold recovery synthesized actions: %+v", actions)
		}
		return err
	})
	if !errors.Is(err, errMissingRecoveryHold) {
		t.Fatalf("recovery refusal = %v (findings %v)", err, result.Findings)
	}
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
	if len(got) != 2 || got[0].EffectRelation != "after" || got[0].Hold == nil ||
		got[0].Hold.Correction == nil || !*got[0].Hold.Correction ||
		got[1].EffectRelation != "unknown" || got[1].Hold == nil ||
		got[1].Hold.Correction != nil {
		t.Fatalf("unexpected recovery relations: %+v", got)
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

func TestStreamWriterReplaysPlainBlockBeforeRestart(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	hold := writerTestHold("terminal")
	policy := CapturePolicy(opts.PolicyHash)
	if err := w.WriteAction(t.Context(), hold, policy); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("terminal flush failed")
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: failure}
	resolution := blockingHoldResolution(hold, "operator", relationAfter, false)
	if err := w.WriteAction(t.Context(), resolution, policy); !errors.Is(err, failure) || !errors.Is(err, ErrHoldBlockRecorded) {
		t.Fatalf("terminal write error = %v, want %v", err, failure)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	public := opts.SigningKey.Public().(ed25519.PublicKey)
	if got := writerTestCount(t, verifyWritten(t, opts.Dir, public), "blocked"); got != 1 {
		t.Fatalf("blocked before restart = %d, want 1", got)
	}
	resolution.Policy = policy.ActionPolicy()
	if got := readRecoveryActions(t, opts.Dir, w.active.id); !reflect.DeepEqual(got, []Action{resolution}) {
		t.Fatalf("successor resolution = %+v, want %+v", got, resolution)
	}
	restarted := requireWriter(t, opts, localWriterStorage())
	if got := readRecoveryActions(t, opts.Dir, restarted.active.id); len(got) != 0 {
		t.Fatalf("restart repeated settled resolution: %+v", got)
	}
}

func TestStreamWriterRecoversHoldAtWireLineLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field func(*Action) *string
	}{
		{"contract rule", func(a *Action) *string {
			a.Contract = &Contract{}
			return &a.Contract.RuleID
		}},
		{"session task label", func(a *Action) *string {
			a.Session = &Session{}
			return &a.Session.TaskLabel
		}},
		{"rulebook ID", func(a *Action) *string { return &a.RulebookID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			w := requireWriter(t, opts, localWriterStorage())
			held := writerTestHold("large-hold")
			held.Session = nil
			held.Policy = PolicySnapshot{}.ActionPolicy()
			field := tc.field(&held)
			*field = "x"
			common := w.common(kindAction, w.active.id, w.active.confirmed.Record, 1)
			line, _, err := w.encode(t.Context(), common, held)
			if err != nil {
				t.Fatal(err)
			}
			*field += strings.Repeat("x", maxLineBytes-len(line))
			if err := w.WriteAction(t.Context(), held, PolicySnapshot{}); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			restarted := requireWriter(t, opts, localWriterStorage())
			repairs := readRecoveryActions(t, opts.Dir, restarted.active.id)
			if len(repairs) != 1 || repairs[0].Session != nil || repairs[0].Contract != nil || repairs[0].RulebookID != "" {
				t.Fatal("repair retained optional hold attribution")
			}
			if err := restarted.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if result.Verdict != "VALID" || writerTestCount(t, result, "blocked") != 1 {
				t.Fatalf("large hold recovery = %s, decisions %+v", result.Verdict, result.Counts.Decisions)
			}
		})
	}
}

func TestStreamWriterStartupReportsHighestUnsupportedActionVersion(t *testing.T) {
	for _, versions := range [][2]int64{{2, 3}, {3, 2}} {
		t.Run(fmt.Sprint(versions), func(t *testing.T) {
			dir := t.TempDir()
			first := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
			for i, version := range versions {
				held := writerTestHold(fmt.Sprintf("hold-%d", i))
				held.Policy = PolicySnapshot{}.ActionPolicy()
				first.addVersion(kindAction, version, held)
			}
			first.close()
			first.write(dir)
			opts := writerTestOptions(dir)
			opts.SigningKey = first.key
			w, err := OpenStreamWriter(t.Context(), opts)
			if err == nil {
				_ = w.Close(t.Context(), nil)
			}
			if err == nil || !strings.Contains(err.Error(), "action body version 3 required") {
				t.Fatalf("wanted highest unsupported version, got %v", err)
			}
		})
	}
}

func TestReceiptHeldRestartBoundaries(t *testing.T) {
	for _, phase := range []string{phaseHold, phaseResolution, phaseIntent} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
			defer cancel()
			opts := writerTestOptions(t.TempDir())
			writer := requireWriter(t, opts, localWriterStorage())
			gate := NewEffectGate(writer)
			policy := CapturePolicy(Digest([]byte("request snapshot")))
			action := writerTestHold("interrupted")
			action.Hold.Parent = ""
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Minute})
			boundary, resume := make(chan struct{}), make(chan struct{})
			sends := make(chan string, 1)
			pause := func() error {
				close(boundary)
				select {
				case <-resume:
					return errors.New("fixture process interruption")
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			held := deferred.HeldAction{
				DeferID: action.Hold.ID, ActionID: action.ActionID,
				Receipt: &deferred.ReceiptHold{
					ConfirmHold: func(ctx context.Context, _ deferred.HeldAction) error {
						return gate.RecordApproval(ctx, action, policy)
					},
					ConfirmResolution: func(ctx context.Context, res deferred.Resolution) (string, error) {
						if phase == phaseHold {
							return "", pause()
						}
						record := blockingHoldResolution(action, res.ResolutionSource, relationAfter, false)
						record.Verdict = res.FinalDecision
						if err := gate.RecordApproval(ctx, record, policy); err != nil {
							return "", err
						}
						if phase == phaseResolution {
							return "", pause()
						}
						return res.FinalDecision, nil
					},
					ConfirmCorrection: func(ctx context.Context, res deferred.Resolution) error {
						return gate.RecordApproval(ctx, blockingHoldResolution(action, res.ResolutionSource, relationAfter, true), policy)
					},
				},
				ResolveReceipt: func(res deferred.Resolution, release deferred.Release) {
					if res.FinalDecision != config.ActionAllow {
						return
					}
					if _, err := gate.AdmitHeld(ctx, writerTestIntent(action.ActionID), policy); err != nil {
						t.Error(err)
						return
					}
					release.Commit()
					if pause() == nil {
						sends <- res.DeferID
					}
				},
			}
			if err := manager.HoldContext(ctx, held); err != nil {
				t.Fatal(err)
			}
			stopped := make(chan error, 1)
			go func() { stopped <- manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceOperator) }()
			select {
			case <-boundary:
			case <-ctx.Done():
				t.Fatal("old process did not reach requested crash boundary")
			}
			if err := abandonWriterReplay(writer); err != nil {
				t.Fatal(err)
			}
			reopened := requireWriter(t, opts, localWriterStorage())
			records := readRecoveryActions(t, opts.Dir, reopened.active.id)
			switch phase {
			case phaseIntent:
				if len(records) != 0 {
					t.Fatalf("restart changed an unsettled intent: %+v", records)
				}
			default:
				corrected := phase == phaseResolution
				relation := "unknown"
				if corrected {
					relation = relationAfter
				}
				if len(records) != 1 {
					t.Fatalf("unexpected settlement records: %+v", records)
				}
				got := records[0]
				if got.ActionID != held.ActionID || got.Phase != phaseResolution || got.Verdict != verdictBlock ||
					got.EffectRelation != relation || got.OutcomeClass != "" || got.Hold == nil ||
					got.Hold.ID != held.DeferID || got.Hold.Parent != "" || got.Hold.ResolutionSource != deferred.SourceRestartRecovery ||
					(got.Hold.Correction != nil) != corrected || corrected && !*got.Hold.Correction {
					t.Fatalf("wrong recovered hold: %+v", got)
				}
			}
			close(resume)
			select {
			case stopErr := <-stopped:
				if (stopErr == nil) != (phase == phaseIntent) {
					t.Fatalf("interrupted resolver returned %v in phase %s", stopErr, phase)
				}
			case <-ctx.Done():
				t.Fatal("old resolver did not unwind")
			}
			if len(sends) != 0 || manager.HeldCount() != 0 {
				t.Fatal("restart fixture left a payload or sent a call")
			}
			if err := reopened.Close(ctx, nil); err != nil {
				t.Fatal(err)
			}
			next := requireWriter(t, opts, localWriterStorage())
			if next.active.confirmed.Seq != 0 || len(readRecoveryActions(t, opts.Dir, next.active.id)) != 0 {
				t.Fatal("second restart did not begin with its own stream open or duplicated hold settlement")
			}
			fresh := deferred.NewManager(deferred.Config{Enabled: true, MaxPending: 1, MaxPendingBytes: 8})
			if err := fresh.Hold(deferred.HeldAction{
				DeferID: "fresh", SizeBytes: 8, Resolve: func(deferred.Resolution) {},
			}); err != nil || fresh.HeldCount() != 1 {
				t.Fatalf("new manager inherited stale capacity: %v", err)
			}
			fresh.ResolveAll(config.ActionBlock, deferred.SourceCancel)
			if err := next.Close(ctx, nil); err != nil {
				t.Fatal(err)
			}
			replayed := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if replayed.Integrity != "ok" || replayed.Verdict != "VALID PREFIX, END UNPROVEN" ||
				len(replayed.Findings) != 1 || replayed.Findings[0].Code != codeEndUnproven {
				t.Fatalf("verify interrupted history: %+v", replayed)
			}
			if phase == phaseIntent && (replayed.Counts.EffectsUnknown == nil || *replayed.Counts.EffectsUnknown != 1) {
				t.Fatalf("unresolved attempted effect: %+v", replayed.Counts)
			}
		})
	}
}
