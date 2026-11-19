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
		ctx, cancel := context.WithCancel(t.Context())
		go scan(ctx, extra)
		synctest.Wait()
		if len(entered) != 0 {
			t.Error("queued projection entered inspection while all slots were in use")
		}
		cancel()
		result := <-extra
		if result.content != nil || !errors.Is(result.err, scanner.ErrTextDLPIncomplete) {
			t.Errorf("canceled projection returned (%v, %v)", result.content, result.err)
		}
		close(release)
		for range slots {
			result := <-active
			if result.content == nil || result.err != nil {
				t.Errorf("active projection returned (%v, %v)", result.content, result.err)
			}
		}

		// A context that is already done when capacity is free either loses
		// the admission select or is admitted and then refused by the
		// post-admission check. The select chooses at random, so repeat it
		// until both branches have run with overwhelming probability.
		done, cancelDone := context.WithCancel(t.Context())
		cancelDone()
		for range 64 {
			if _, content, err := rec.ScanReceiptContent(done, recorderSessionProducer, []byte(`{"session_id":"ordinary receipt"}`)); content != nil || !errors.Is(err, scanner.ErrTextDLPIncomplete) {
				t.Errorf("projection canceled with free capacity returned (%v, %v)", content, err)
			}
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
		again := make(chan scanResult, slots)
		for range slots {
			go scan(t.Context(), again)
			<-refilled
		}
		close(refill)
		for range slots {
			if result := <-again; result.content == nil || result.err != nil {
				t.Errorf("refilled projection returned (%v, %v)", result.content, result.err)
			}
		}
	})
}
