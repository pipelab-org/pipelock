// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func writerTestIntent(id string) Action {
	attempt := int64(1)
	return Action{
		ActionID: id, ActionType: "read", Actor: "example",
		Attempt: &attempt, Caller: Caller{Authn: "none"},
		Data:           Data{SideEffectClass: "read", Reversibility: "unknown"},
		EffectBoundary: "upstream_send", EffectRelation: "before",
		Method: http.MethodGet, Phase: phaseIntent, Principal: "local",
		Target: "https://api.vendor.example", Transport: "fetch", Verdict: verdictAllow,
	}
}

func writerTestCount(t *testing.T, result Result, state string) int64 {
	t.Helper()
	if result.Counts.Decisions == nil {
		t.Fatalf("no decision count: %+v", result)
	}
	for _, count := range *result.Counts.Decisions {
		if count.State == state {
			return count.Count
		}
	}
	return 0
}

func TestStreamWriterActionBarrierAndRepair(t *testing.T) {
	for _, faultKind := range []string{"write", "flush", "success"} {
		t.Run(faultKind, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			w := requireWriter(t, opts, localWriterStorage())
			var effects atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
				effects.Add(1)
				resp.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(upstream.Close)
			public := opts.SigningKey.Public().(ed25519.PublicKey)
			failure := errors.New("storage failure")
			switch faultKind {
			case "write":
				w.active.file = errorWriterFile{StreamFile: w.active.file, writeErr: failure}
			case "flush":
				w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: failure}
			}
			intent := writerTestIntent("request")
			policy := CapturePolicy(Digest([]byte("original snapshot")))
			err := w.WriteAction(t.Context(), intent, policy)
			if err == nil {
				before := verifyWritten(t, opts.Dir, public)
				if writerTestCount(t, before, "outcome_unknown") != 1 || effects.Load() != 0 {
					t.Fatalf("expected recorded intent before a request reaches upstream: %+v", before)
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := upstream.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if err := resp.Body.Close(); err != nil {
					t.Fatal(err)
				}
				outcome := intent
				outcome.Phase, outcome.EffectRelation, outcome.OutcomeClass = phaseOutcome, relationAfter, "completed"
				if err := w.WriteAction(t.Context(), outcome, policy); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, failure) || !errors.Is(err, ErrEffectNotReleased) {
				t.Fatalf("unexpected intent error: %v", err)
			}
			if err := w.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result := verifyWritten(t, opts.Dir, public)
			if faultKind == "success" {
				if effects.Load() != 1 || writerTestCount(t, result, "completed") != 1 {
					t.Fatalf("successful effect or outcome missing: %d, %+v", effects.Load(), result)
				}
			} else if effects.Load() != 0 || writerTestCount(t, result, outcomeNotReleased) != 1 {
				t.Fatalf("failed intent released an effect or did not settle: %d, %+v", effects.Load(), result)
			}
		})
	}
}

func TestStreamWriterSettlesOutcomeAfterWriteErrors(t *testing.T) {
	for _, tc := range []struct {
		name          string
		secondFault   int
		thirdFault    int
		failSuccessor bool
	}{
		{name: "repair append fails", secondFault: 6},
		{name: "repair append fails on consecutive successors", secondFault: 6, thirdFault: 11, failSuccessor: true},
		{name: "successor link fails", secondFault: 4, failSuccessor: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			opts.Heartbeat = 0
			fault := writerReplayFault{}
			w, err := openStreamWriter(t.Context(), opts, fault.storage(opts.Dir))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = abandonWriterReplay(w) })
			policy := CapturePolicy(Digest([]byte("request config")))
			intent := writerTestIntent("request")
			if err := w.WriteAction(t.Context(), intent, policy); err != nil {
				t.Fatal(err)
			}
			outcome := intent
			outcome.Phase, outcome.EffectRelation, outcome.OutcomeClass = phaseOutcome, relationAfter, "completed"
			fault = writerReplayFault{step: writerReplayStep{FaultAt: 1, ExtraFaultAt: tc.secondFault}, additionalFaultAt: tc.thirdFault}
			if err := w.WriteAction(t.Context(), outcome, policy); !errors.Is(err, errWriterReplay) {
				t.Fatalf("outcome write error = %v, want %v", err, errWriterReplay)
			}
			if tc.failSuccessor {
				fault = writerReplayFault{}
				if err := w.WriteAction(t.Context(), writerTestIntent("later"), policy); err == nil || len(fault.calls) != 0 {
					t.Fatalf("writer resumed admission: error = %v, storage calls = %v", err, fault.calls)
				}
			}
			if err := abandonWriterReplay(w); err != nil {
				t.Fatal(err)
			}
			w = nil

			result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if tc.failSuccessor {
				if got := writerTestCount(t, result, "outcome_unknown"); got != 1 {
					t.Fatalf("unknown outcomes = %d, want 1", got)
				}
				return
			}
			if got := writerTestCount(t, result, "completed"); got != 1 {
				t.Fatalf("completed outcomes = %d, want 1", got)
			}
			streams := result.Histories[0].Streams
			if len(streams) != 3 {
				t.Fatalf("streams after losing writer state = %d, want 3", len(streams))
			}
			for _, stream := range streams {
				if stream.End == "superseded_write_error" && stream.Tip != nil && stream.Tip.Seq == 0 {
					return
				}
			}
			t.Fatalf("missing write-error pin at the failed repair stream opening: %+v", streams)
		})
	}
}

type syncCallbackFile struct {
	StreamFile
	syncCallback func()
}

func (f syncCallbackFile) Sync() error {
	err := f.StreamFile.Sync()
	f.syncCallback()
	return err
}

func TestStreamWriterActionCancellationAndAttribution(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w.active.file = syncCallbackFile{StreamFile: w.active.file, syncCallback: cancel}
	intent := writerTestIntent("cancelled")
	// Supplied body attribution must be ignored in favor of the captured
	// policy, including when the producer did not capture one.
	intent.Policy = ActionPolicy{Source: "request_snapshot", Hash: opts.PolicyHash}
	if err := w.WriteAction(ctx, intent, PolicySnapshot{}); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrEffectNotReleased) {
		t.Fatalf("wanted cancellation after intent flush, got %v", err)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	assertActionPolicy(t, opts.Dir, w.active.id, 1, ActionPolicy{Source: "unavailable"})
	assertActionPolicy(t, opts.Dir, w.active.id, 2, ActionPolicy{Source: "unavailable"})
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if writerTestCount(t, result, outcomeNotReleased) != 1 {
		t.Fatalf("cancelled intent did not settle: %+v", result)
	}
}

func TestStreamWriterContractGenerationBounds(t *testing.T) {
	w := requireWriter(t, writerTestOptions(t.TempDir()), localWriterStorage())
	intent := writerTestIntent("contract")
	for _, generation := range []uint64{maxInteger + 1, math.MaxInt64 + 1} {
		intent.SetAttribution(receipt.EmitOpts{ContractGeneration: generation})
		if err := w.WriteAction(t.Context(), intent, PolicySnapshot{}); err == nil {
			t.Fatalf("writer accepted out-of-range contract generation %d", generation)
		}
		if w.active.confirmed.Seq != 0 {
			t.Fatalf("out-of-range generation %d advanced the stream", generation)
		}
	}

	intent.SetAttribution(receipt.EmitOpts{ContractGeneration: maxInteger})
	if intent.Contract == nil || intent.Contract.Generation == nil || *intent.Contract.Generation != maxInteger {
		t.Fatalf("contract attribution lost the maximum wire generation: %+v", intent.Contract)
	}
	if err := w.WriteAction(t.Context(), intent, PolicySnapshot{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestStreamWriterSettlesCancelledActionAfterWriteError(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Heartbeat = 0
	fault := writerReplayFault{}
	w, err := openStreamWriter(t.Context(), opts, fault.storage(opts.Dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = abandonWriterReplay(w) })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w.active.file = syncCallbackFile{StreamFile: w.active.file, syncCallback: cancel}
	// The intent flush succeeds. The following refusal append writes no bytes.
	initialStream := w.active.id
	fault = writerReplayFault{step: writerReplayStep{FaultAt: 3}}
	if err := w.WriteAction(ctx, writerTestIntent("cancelled"), PolicySnapshot{}); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrEffectNotReleased) {
		t.Fatalf("wanted cancellation after intent flush, got %v", err)
	}
	if err := abandonWriterReplay(w); err != nil {
		t.Fatal(err)
	}
	w = nil

	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	streams := result.Histories[0].Streams
	if len(streams) != 2 {
		t.Fatalf("expected a successor: %+v", streams)
	}
	for _, stream := range streams {
		if stream.Stream == initialStream && (stream.End != "superseded_write_error" || stream.Tip == nil || stream.Tip.Seq != 1) {
			t.Fatalf("failed stream did not pin the confirmed intent: %+v", stream)
		}
	}
	if got := writerTestCount(t, result, outcomeNotReleased); got != 1 {
		t.Fatalf("refused outcomes after losing writer state = %d, want 1", got)
	}
}

func assertActionPolicy(t *testing.T, dir, stream string, seq int64, want ActionPolicy) {
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
	for line := range bytes.SplitAfterSeq(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		record, code := parseLine(line, "")
		if code != "" {
			t.Fatal(code)
		}
		if record.Seq == seq {
			var got Action
			if err := json.Unmarshal(record.Body, &got); err != nil {
				t.Fatal(err)
			}
			if got.Policy != want {
				t.Fatalf("policy = %+v, want %+v", got.Policy, want)
			}
			return
		}
	}
	t.Fatalf("record %d missing", seq)
}

type waitingReceiptContext struct {
	context.Context
	waiting chan struct{}
}

func (ctx waitingReceiptContext) Done() <-chan struct{} {
	close(ctx.waiting)
	return ctx.Context.Done()
}

func TestStreamWriterCancelsWaitBehindFlush(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	effects := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		effects <- req.URL.Path
		resp.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	admitAndSend := func(ctx context.Context, id string) error {
		if err := w.WriteAction(ctx, writerTestIntent(id), PolicySnapshot{}); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/"+id, nil)
		if err != nil {
			return err
		}
		resp, err := upstream.Client().Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	releaseFlush := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(releaseFlush)
	deadline, stop := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer stop()
	w.active.file = syncCallbackFile{
		StreamFile: w.active.file,
		syncCallback: sync.OnceFunc(func() {
			close(entered)
			<-resume
		}),
	}
	first := make(chan error, 1)
	go func() {
		first <- admitAndSend(t.Context(), "first")
	}()
	select {
	case <-entered:
	case err := <-first:
		t.Fatalf("first send finished without waiting for the flush: %v", err)
	case <-deadline.Done():
		t.Fatal("first intent did not reach the flush")
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctxWithWait := waitingReceiptContext{Context: ctx, waiting: make(chan struct{})}
	second := make(chan error, 1)
	go func() {
		second <- admitAndSend(ctxWithWait, "second")
	}()
	select {
	case <-ctxWithWait.waiting:
	case <-deadline.Done():
		t.Fatal("second intent did not wait for writer admission")
	}
	cancel()
	select {
	case err := <-second:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled waiter: %v", err)
		}
	case <-deadline.Done():
		t.Fatal("second intent did not return after cancellation")
	}
	beforeConfirmation := len(effects)
	releaseFlush()
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-deadline.Done():
		t.Fatal("first send did not return after the flush")
	}
	if beforeConfirmation != 0 || len(effects) != 1 {
		t.Fatalf("endpoint observed %d calls before confirmation and %d in total", beforeConfirmation, len(effects))
	}
	if got := <-effects; got != "/first" {
		t.Fatalf("endpoint observed %q, want /first", got)
	}
	if w.active.confirmed.Seq != 1 || w.durability.DurabilityBlocks != 0 {
		t.Fatalf("cancelled waiter changed receipts or counters: %+v / %+v", w.active.confirmed, w.durability)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if writerTestCount(t, result, "outcome_unknown") != 1 {
		t.Fatalf("cancelled waiter entered the history: %+v", result)
	}
}

func TestStreamWriterRefusesUnscannedCallerIdentity(t *testing.T) {
	const subject = "example-subject"
	for _, tc := range []struct {
		name   string
		result scanner.TextDLPResult
		want   error
	}{
		{name: "identity finding", result: scanner.TextDLPResult{}, want: receiptcontent.ErrRejected},
		{name: "incomplete scan", result: scanner.TextDLPResult{Incomplete: true}, want: scanner.ErrTextDLPIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			opts.Coverage.ContentScan = true
			seen := false
			opts.Detector = func(_ context.Context, text string) scanner.TextDLPResult {
				if text == subject {
					seen = true
					return tc.result
				}
				return scanner.TextDLPResult{Clean: true}
			}
			w := requireWriter(t, opts, localWriterStorage())
			action := writerTestIntent("request")
			action.Caller = Caller{
				Authn: "mcp_door_verified", Subject: subject, Issuer: "issuer.vendor.example",
				Resource: "api.vendor.example", ClientID: "example-client",
			}
			if err := w.WriteAction(t.Context(), action, PolicySnapshot{}); !errors.Is(err, tc.want) {
				t.Fatalf("unverified caller identity reached writer: %v", err)
			}
			if !seen || w.active.confirmed.Seq != 0 {
				t.Fatalf("caller field scan or non-publication missing: seen=%t seq=%d", seen, w.active.confirmed.Seq)
			}
			if err := w.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamWriterAdmissionBatchReservesExactCount(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	ctx := t.Context()
	policy := CapturePolicy(Digest(nil))
	first, second := writerTestIntent("first"), writerTestIntent("second")
	if err := w.WriteAdmissionBatch(ctx, []Action{first, first}, policy); err == nil || w.active.confirmed.Seq != 0 {
		t.Fatalf("invalid batch advanced the confirmed position: seq=%d error=%v", w.active.confirmed.Seq, err)
	}
	if err := w.WriteAdmissionBatch(ctx, []Action{first, second}, policy); err != nil {
		t.Fatal(err)
	}
	if w.active.confirmed.Seq != 2 {
		t.Fatalf("confirmed sequence %d, want 2", w.active.confirmed.Seq)
	}
	public := opts.SigningKey.Public().(ed25519.PublicKey)
	if result := verifyWritten(t, opts.Dir, public); writerTestCount(t, result, "outcome_unknown") != 2 {
		t.Fatalf("batch records were not verified before return: %+v", result)
	}
	failure := errors.New("batch flush failed")
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: failure}
	third, fourth := writerTestIntent("third"), writerTestIntent("fourth")
	if err := w.WriteAdmissionBatch(ctx, []Action{third, fourth}, policy); !errors.Is(err, failure) {
		t.Fatalf("batch reported success after a failed flush: %v", err)
	}
	result := verifyWritten(t, opts.Dir, public)
	if writerTestCount(t, result, "outcome_unknown") != 2 || writerTestCount(t, result, "not_released") != 2 {
		t.Fatalf("batch refusal did not settle both unconfirmed allowances: %+v", result)
	}
}

func TestStreamWriterAdmissionBatchRefusals(t *testing.T) {
	policy := CapturePolicy(Digest(nil))
	first, second := writerTestIntent("first"), writerTestIntent("second")
	for _, fault := range []string{"cancelled", "duplicate", "wrong phase", "segment limit", "failed flush", "cancelled flush", "closed"} {
		t.Run(fault, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			w := requireWriter(t, opts, localWriterStorage())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			actions := []Action{first, second}
			var want string
			switch fault {
			case "cancelled":
				cancel()
				want = "context canceled"
			case "duplicate":
				actions[1] = first
				want = "repeats an action ID"
			case "wrong phase":
				actions[1].Phase = phaseOutcome
				want = "requires admission actions"
			case "segment limit":
				w.fileBytes = maxLineBytes
				want = "exceeds the segment limit"
			case "failed flush":
				w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: errWriterReplay}
			case "cancelled flush":
				w.active.file = syncCallbackFile{StreamFile: w.active.file, syncCallback: sync.OnceFunc(cancel)}
			case "closed":
				if err := w.Close(ctx, nil); err != nil {
					t.Fatal(err)
				}
				want = "closed"
			}
			before := w.active.confirmed
			err := w.WriteAdmissionBatch(ctx, actions, policy)
			if fault == "segment limit" && w.active.confirmed != before {
				t.Fatalf("oversized batch advanced confirmation: %v to %v", before, w.active.confirmed)
			}
			w.fileBytes = writerFileBytes
			if want != "" {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("batch error = %v, want %q", err, want)
				}
				return
			}
			if !errors.Is(err, ErrEffectNotReleased) {
				t.Fatalf("batch error = %v, want withheld effect", err)
			}
			if err := w.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if got := writerTestCount(t, result, outcomeNotReleased); got != 2 {
				t.Fatalf("withheld outcomes = %d, want 2", got)
			}
		})
	}
	var w *StreamWriter
	if err := w.WriteAdmissionBatch(t.Context(), nil, policy); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteAdmissionBatch(t.Context(), []Action{first}, policy); err == nil {
		t.Fatal("nil writer accepted a nonempty batch")
	}
}

func TestStreamWriterReportsDurableCancelledHoldCorrection(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	policy := CapturePolicy(Digest(nil))
	hold := writerTestHold("cancelled-hold")
	hold.Hold.Parent = ""
	if err := w.WriteAction(t.Context(), hold, policy); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w.active.file = syncCallbackFile{StreamFile: w.active.file, syncCallback: sync.OnceFunc(cancel)}
	decision := hold
	decision.Phase, decision.EffectRelation, decision.Verdict = phaseResolution, relationAfter, verdictAllow
	decision.Hold = &Hold{ID: hold.Hold.ID, ResolutionPolicy: hold.Hold.Policy, ResolutionSource: "approval"}
	err := w.WriteAction(ctx, decision, policy)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrHoldBlockRecorded) {
		t.Fatalf("resolution = %v, want cancelled with durable correction", err)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if result.Integrity != "ok" || writerTestCount(t, result, "blocked") != 1 {
		t.Fatalf("cancelled hold did not verify with one block: %+v", result)
	}
}

func TestStreamWriterAdmissionBatchRejectsOptionalPostEffectDecision(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Coverage.ReceiptsRequired = false
	w := requireWriter(t, opts, localWriterStorage())
	for _, relation := range []string{relationAfter, "unknown"} {
		action := writerTestIntent("already-attempted-" + relation)
		action.Attempt = nil
		action.Phase = phaseDecision
		action.EffectRelation = relation
		if err := w.WriteAdmissionBatch(t.Context(), []Action{action}, PolicySnapshot{}); err == nil {
			t.Fatalf("admission accepted an action with relation %q", relation)
		}
		if err := w.WriteAction(t.Context(), action, PolicySnapshot{}); err != nil {
			t.Fatalf("ordinary write rejected relation %q: %v", relation, err)
		}
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if result.Verdict != "VALID" {
		t.Fatalf("ordinary post-effect decisions did not verify: %+v", result)
	}
}

func TestStreamWriterRejectsInvalidAdmissionsWithoutAppending(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Heartbeat = 0
	w := requireWriter(t, opts, localWriterStorage())
	intent := writerTestIntent("intent")
	invalid := intent
	invalid.Attempt = nil
	var unavailable *StreamWriter
	for _, tc := range []struct {
		name string
		run  func() error
		want string
	}{
		{"missing action writer", func() error { return unavailable.WriteAction(t.Context(), intent, PolicySnapshot{}) }, "writer is unavailable"},
		{"intent without attempt", func() error { return w.WriteAction(t.Context(), invalid, PolicySnapshot{}) }, "does not match its effect phase"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("write = %v, want %q", err, tc.want)
			}
		})
	}
	if w.active.confirmed.Seq != 0 {
		t.Fatalf("refusal changed the stream tip: %+v", w.active.confirmed)
	}
	if err := w.WriteAction(t.Context(), intent, PolicySnapshot{}); err != nil {
		t.Fatalf("valid admission after refusal: %v", err)
	}
}

func TestStreamWriterClosesInterruptedHoldAdmission(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		phase string
	}{
		{"unconfirmed hold", errWriterReplay, phaseDecision},
		{"canceled confirmed hold", context.Canceled, phaseResolution},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			opts.Heartbeat = 0
			w := requireWriter(t, opts, localWriterStorage())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if errors.Is(tc.cause, context.Canceled) {
				w.active.file = syncCallbackFile{StreamFile: w.active.file, syncCallback: sync.OnceFunc(cancel)}
			} else {
				w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: tc.cause}
			}

			hold := writerTestHold("interrupted")
			hold.Hold.Parent = ""
			if err := w.WriteAction(ctx, hold, PolicySnapshot{}); !errors.Is(err, tc.cause) || !errors.Is(err, ErrEffectNotReleased) {
				t.Fatalf("write hold = %v, want %v and effect withheld", err, tc.cause)
			}
			if err := w.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			actions := readRecoveryActions(t, opts.Dir, w.active.id)
			if len(actions) == 0 {
				t.Fatal("interrupted hold left no signed settlement")
			}
			settlement := actions[len(actions)-1]
			if settlement.ActionID != hold.ActionID || settlement.Phase != tc.phase || settlement.Verdict != verdictBlock ||
				settlement.EffectRelation != relationNotAttempted {
				t.Fatalf("settlement = %+v, want %s block without an attempt", settlement, tc.phase)
			}
			if tc.phase == phaseResolution {
				if len(actions) != 2 || actions[0].Phase != phaseHold || settlement.Hold == nil ||
					settlement.Hold.ID != hold.Hold.ID || settlement.Hold.ResolutionSource != "request_cancelled" {
					t.Fatalf("cancellation did not settle the confirmed hold: %+v", actions)
				}
			} else if len(actions) != 1 || settlement.Hold != nil {
				t.Fatalf("failure retained an unconfirmed hold in the successor: %+v", actions)
			}
			result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if got := writerTestCount(t, result, "blocked"); got != 1 {
				t.Fatalf("blocked decisions = %d, want 1", got)
			}
		})
	}
}

func TestStreamWriterRejectsResolutionWithoutMatchingHold(t *testing.T) {
	w := requireWriter(t, writerTestOptions(t.TempDir()), localWriterStorage())
	held := writerTestHold("request")
	if err := w.WriteAction(t.Context(), held, PolicySnapshot{}); err != nil {
		t.Fatal(err)
	}
	tip := w.active.confirmed
	for _, tc := range []struct{ action, hold string }{
		{"request", "other-hold"}, {"other-request", held.Hold.ID},
	} {
		resolution := blockingHoldResolution(held, "operator", relationAfter, false)
		resolution.ActionID, resolution.Hold.ID = tc.action, tc.hold
		if err := w.WriteAction(t.Context(), resolution, PolicySnapshot{}); err == nil || w.active.confirmed != tip {
			t.Fatalf("invalid resolution advanced the stream: %v", err)
		}
	}
}

func TestStreamWriterOptionalBatchRejectsDecision(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Coverage.ReceiptsRequired = false
	w := requireWriter(t, opts, localWriterStorage())
	decision := writerTestIntent("decision")
	decision.Phase, decision.Attempt = phaseDecision, nil
	if err := w.WriteAdmissionBatch(t.Context(), []Action{decision}, PolicySnapshot{}); err == nil || w.active.confirmed.Seq != 0 {
		t.Fatalf("optional batch accepted a decision: %v", err)
	}
}

func TestStreamWriterDoesNotReportUnconfirmedRefusal(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Heartbeat = 0
	fault := writerReplayFault{}
	w := requireWriter(t, opts, fault.storage(opts.Dir))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w.active.file = syncCallbackFile{StreamFile: w.active.file, syncCallback: cancel}
	// Confirm the intent, then fail the refusal write and its retry.
	fault = writerReplayFault{step: writerReplayStep{FaultAt: 3, ExtraFaultAt: 8}}
	err := w.WriteAction(ctx, writerTestIntent("cancelled"), PolicySnapshot{})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, errWriterReplay) || errors.Is(err, ErrEffectNotReleased) {
		t.Fatalf("unconfirmed refusal reported as durable: %v (calls %v)", err, fault.calls)
	}
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if writerTestCount(t, result, outcomeNotReleased) != 0 || writerTestCount(t, result, "outcome_unknown") != 1 {
		t.Fatalf("unexpected decision states: %+v", result.Counts.Decisions)
	}
}

func TestStreamWriterStopsAfterDetachedRepairTimeout(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Coverage.ContentScan = true
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	watchdog, stop := context.WithTimeout(t.Context(), testwait.Deadline(8*time.Second))
	defer stop()
	opts.Detector = func(scanCtx context.Context, _ string) scanner.TextDLPResult {
		if ctx.Err() != nil {
			select {
			case <-scanCtx.Done():
			case <-watchdog.Done():
			}
		}
		return scanner.TextDLPResult{Clean: true}
	}
	w := requireWriter(t, opts, localWriterStorage())
	w.active.file = syncCallbackFile{StreamFile: w.active.file, syncCallback: sync.OnceFunc(cancel)}
	err := w.WriteAction(ctx, writerTestIntent("repair-timeout"), PolicySnapshot{})
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrEffectNotReleased) {
		t.Fatalf("unconfirmed repair error = %v, want deadline without durable refusal", err)
	}
	if err := w.WriteHeartbeat(t.Context()); !errors.Is(err, ErrWriterUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("heartbeat error = %v, want verified restart required", err)
	}
	if err := w.Close(t.Context(), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close error = %v, want repair deadline", err)
	}
}
