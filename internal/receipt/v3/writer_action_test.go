// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"

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
		failSuccessor bool
	}{
		{name: "repair append fails", secondFault: 6},
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
			fault = writerReplayFault{step: writerReplayStep{FaultAt: 1, ExtraFaultAt: tc.secondFault}}
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
	fault = writerReplayFault{step: writerReplayStep{FaultAt: 3}}
	if err := w.WriteAction(ctx, writerTestIntent("cancelled"), PolicySnapshot{}); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrEffectNotReleased) {
		t.Fatalf("wanted cancellation after intent flush, got %v", err)
	}
	if err := abandonWriterReplay(w); err != nil {
		t.Fatal(err)
	}
	w = nil

	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
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
	<-entered

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctxWithWait := waitingReceiptContext{Context: ctx, waiting: make(chan struct{})}
	second := make(chan error, 1)
	go func() {
		second <- admitAndSend(ctxWithWait, "second")
	}()
	<-ctxWithWait.waiting
	cancel()
	err := <-second
	beforeConfirmation := len(effects)
	close(resume)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
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
