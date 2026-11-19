// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"testing/synctest"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestReceiptDetectorCacheBinding caches only the detector whose scanner
// generation is fixed for the recorder's lifetime. An arbitrary callback may
// change its answer, so New never caches it.
func TestReceiptDetectorCacheBinding(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "cache fixture", Regex: "receipt-secret-fixture", Severity: config.SeverityHigh})
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	bound, err := NewWithScanner(Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := bound.Close(); err != nil {
			t.Error(err)
		}
	}()
	if bound.contentCache == nil {
		t.Fatal("scanner-bound recorder has no receipt content cache")
	}
	det := bound.ReceiptDetector()
	for range 2 {
		if res := det(t.Context(), "ordinary receipt"); !res.Clean {
			t.Fatalf("clean control blocked: %+v", res)
		}
		if res := det(t.Context(), "receipt-secret-fixture"); res.Clean || len(res.Matches) != 1 {
			t.Fatalf("cached detector missed generation rule: %+v", res)
		}
	}
	if n := bound.contentCache.Len(); n != 1 {
		t.Fatalf("cache remembers %d texts, want only the clean one", n)
	}

	plain, err := New(Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc.ScanTextForDLP, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plain.Close(); err != nil {
			t.Error(err)
		}
	}()
	if plain.contentCache != nil {
		t.Fatal("arbitrary callback was cached")
	}
	off, err := NewWithScanner(Config{Enabled: true, Dir: t.TempDir()}, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := off.Close(); err != nil {
			t.Error(err)
		}
	}()
	if off.contentCache != nil || off.ReceiptDetector() != nil {
		t.Fatal("recorder without redaction built a receipt detector")
	}
}

func TestReceiptContentBoundsConcurrentInspection(t *testing.T) {
	sc := scanner.MustNew(config.Defaults())
	t.Cleanup(sc.Close)
	dir := t.TempDir()
	synctest.Test(t, func(t *testing.T) {
		slots := runtime.GOMAXPROCS(0)
		rec, err := NewWithScanner(Config{Enabled: true, Dir: dir, Redact: true}, sc, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := rec.Close(); err != nil {
				t.Error(err)
			}
		})
		release := make(chan struct{})
		entered := make(chan struct{}, slots+1)
		rec.contentDetector = func(ctx context.Context, _ string) scanner.TextDLPResult {
			select {
			case <-release:
				return scanner.TextDLPResult{Clean: true}
			default:
			}
			entered <- struct{}{}
			select {
			case <-release:
				return scanner.TextDLPResult{Clean: true}
			case <-ctx.Done():
				return scanner.TextDLPResult{Incomplete: true}
			}
		}
		type scanResult struct {
			content *ContentScan
			err     error
		}
		scan := func(ctx context.Context, result chan<- scanResult) {
			_, content, err := rec.ScanReceiptContent(ctx, recorderSessionProducer, []byte(`{"session_id":"ordinary receipt"}`))
			result <- scanResult{content, err}
		}
		active := make(chan scanResult, slots)
		for range slots {
			go scan(t.Context(), active)
			<-entered
		}
		extra := make(chan scanResult, 1)
		queued := make(chan struct{}, 1)
		rec.SetContentScanWaitForTest(func() { queued <- struct{}{} })
		ctx, cancel := context.WithCancel(t.Context())
		go scan(ctx, extra)
		<-queued
		rec.SetContentScanWaitForTest(nil)
		synctest.Wait()
		if len(entered) != 0 {
			t.Error("queued projection entered inspection while all slots were in use")
		}
		cancel()
		result := <-extra
		if result.content != nil || !errors.Is(result.err, scanner.ErrTextDLPIncomplete) || !errors.Is(result.err, context.Canceled) {
			t.Errorf("canceled projection returned (%v, %v)", result.content, result.err)
		}
		close(release)
		for range slots {
			result := <-active
			if result.content == nil || result.err != nil {
				t.Errorf("active projection returned (%v, %v)", result.content, result.err)
			}
		}

		// Free capacity must not allow a canceled caller to start inspection.
		done, cancelDone := context.WithCancel(t.Context())
		cancelDone()
		if _, content, err := rec.ScanReceiptContent(done, recorderSessionProducer, []byte(`{"session_id":"ordinary receipt"}`)); content != nil || !errors.Is(err, context.Canceled) {
			t.Errorf("projection canceled with free capacity returned (%v, %v)", content, err)
		}

		// An active detector can also report incomplete inspection on cancellation.
		scanning := make(chan struct{})
		rec.contentDetector = func(ctx context.Context, _ string) scanner.TextDLPResult {
			close(scanning)
			<-ctx.Done()
			return scanner.TextDLPResult{Incomplete: true}
		}
		activeCtx, cancelActive := context.WithCancel(t.Context())
		go scan(activeCtx, extra)
		<-scanning
		cancelActive()
		result = <-extra
		if result.content != nil || !errors.Is(result.err, scanner.ErrTextDLPIncomplete) || !errors.Is(result.err, context.Canceled) {
			t.Errorf("projection canceled during inspection returned (%v, %v)", result.content, result.err)
		}
		// A projection error after admission still returns its slot.
		if _, content, err := rec.ScanReceiptContent(t.Context(), recorderSessionProducer, []byte(`not json`)); content != nil || err == nil {
			t.Errorf("malformed projection returned (%v, %v)", content, err)
		}

		// Every slot is still available: fill them all again.
		refill := make(chan struct{})
		refilled := make(chan struct{}, slots)
		rec.contentDetector = func(context.Context, string) scanner.TextDLPResult {
			select {
			case <-refill:
				return scanner.TextDLPResult{Clean: true}
			default:
			}
			refilled <- struct{}{}
			<-refill
			return scanner.TextDLPResult{Clean: true}
		}
		again := make(chan scanResult, slots+1)
		for range slots {
			go scan(t.Context(), again)
			<-refilled
		}
		// One more scan queues and is admitted once a slot frees.
		rec.SetContentScanWaitForTest(func() { queued <- struct{}{} })
		go scan(t.Context(), again)
		<-queued
		rec.SetContentScanWaitForTest(nil)
		close(refill)
		for range slots + 1 {
			if result := <-again; result.content == nil || result.err != nil {
				t.Errorf("refilled projection returned (%v, %v)", result.content, result.err)
			}
		}
	})
}

func TestSetContentScanWaitForTestNilRecorder(t *testing.T) {
	var rec *Recorder
	rec.SetContentScanWaitForTest(func() {})
	rec.SetContentScanWaitForTest(nil)
}
