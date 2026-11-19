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
				w.active.file = errorWriterFile{writerFile: w.active.file, writeErr: failure}
			case "flush":
				w.active.file = errorWriterFile{writerFile: w.active.file, syncErr: failure}
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
			} else if !errors.Is(err, failure) {
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

type syncCallbackFile struct {
	writerFile
	syncCallback func()
}

func (f syncCallbackFile) Sync() error {
	err := f.writerFile.Sync()
	f.syncCallback()
	return err
}

func TestStreamWriterActionCancellationAndAttribution(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w.active.file = syncCallbackFile{writerFile: w.active.file, syncCallback: cancel}
	intent := writerTestIntent("cancelled")
	// Supplied body attribution must be ignored in favor of the captured
	// policy, including when the producer did not capture one.
	intent.Policy = ActionPolicy{Source: "request_snapshot", Hash: opts.PolicyHash}
	if err := w.WriteAction(ctx, intent, PolicySnapshot{}); !errors.Is(err, context.Canceled) {
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
	entered, resume := make(chan struct{}), make(chan struct{})
	w.active.file = syncCallbackFile{
		writerFile: w.active.file,
		syncCallback: sync.OnceFunc(func() {
			close(entered)
			<-resume
		}),
	}
	first := make(chan error, 1)
	go func() {
		first <- w.WriteAction(t.Context(), writerTestIntent("first"), PolicySnapshot{})
	}()
	<-entered

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctxWithWait := waitingReceiptContext{Context: ctx, waiting: make(chan struct{})}
	second := make(chan error, 1)
	go func() {
		second <- w.WriteAction(ctxWithWait, writerTestIntent("second"), PolicySnapshot{})
	}()
	<-ctxWithWait.waiting
	cancel()
	err := <-second
	close(resume)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
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
