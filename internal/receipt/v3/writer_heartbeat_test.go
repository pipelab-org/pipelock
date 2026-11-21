// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestStreamWriterStartsConfiguredHeartbeats(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Heartbeat = time.Second
	storage := localWriterStorage()
	createTemp := storage.createTemp
	heartbeatFlushed := make(chan struct{})
	storage.createTemp = func(dir, pattern string) (StreamFile, error) {
		f, err := createTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		newStream := true
		notify := sync.OnceFunc(func() { close(heartbeatFlushed) })
		return syncCallbackFile{StreamFile: f, syncCallback: func() {
			if newStream {
				newStream = false
				return
			}
			notify()
		}}, nil
	}
	w := requireWriter(t, opts, storage)
	// Observe the first append after the opening sync.
	select {
	case <-heartbeatFlushed:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled heartbeat did not flush")
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if w.open.HeartbeatSeconds == nil || *w.open.HeartbeatSeconds != 1 || w.active.beat < 1 {
		t.Fatalf("configured cadence or confirmed heartbeat missing: cadence=%v beat=%d", w.open.HeartbeatSeconds, w.active.beat)
	}
	verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
}

func TestStreamWriterHeartbeatCancellationPreservesSequence(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Coverage.ContentScan = true
	opts.Detector = func(context.Context, string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: true}
	}
	w := requireWriter(t, opts, localWriterStorage())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := w.WriteHeartbeat(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled heartbeat: %v", err)
	}
	if w.active.confirmed.Seq != 0 || w.active.beat != 0 {
		t.Fatal("canceled heartbeat advanced the stream")
	}
	if err := w.WriteHeartbeat(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w.active.confirmed.Seq != 1 || w.active.beat != 1 {
		t.Fatal("scanned heartbeat did not advance the stream")
	}
}

func TestStreamWriterHeartbeatAndRolloverAfterClose(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	closed := w.active.confirmed
	if err := w.WriteHeartbeat(t.Context()); !errors.Is(err, ErrWriterUnavailable) {
		t.Fatalf("heartbeat after close: %v", err)
	}
	if err := w.Rollover(t.Context()); !errors.Is(err, ErrWriterUnavailable) {
		t.Fatalf("rollover after close: %v", err)
	}
	if w.active.confirmed != closed {
		t.Fatalf("closed stream changed from %+v to %+v", closed, w.active.confirmed)
	}
}
