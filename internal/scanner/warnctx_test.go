// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestWithDLPWarnContextNilUsesBackground(t *testing.T) {
	t.Parallel()

	wc := DLPWarnContext{
		Method:    http.MethodGet,
		URL:       "https://api.vendor.example/collect",
		Transport: "fetch",
		ClientIP:  "192.0.2.10",
	}
	var parent context.Context
	ctx := WithDLPWarnContext(parent, wc)
	if ctx == nil {
		t.Fatal("WithDLPWarnContext(nil parent) returned nil context")
	}
	got := DLPWarnContextFromCtx(ctx)
	if got != wc {
		t.Fatalf("round-trip from nil parent = %+v, want %+v", got, wc)
	}
}

func TestDLPWarnContextFromCtxNilAndUnset(t *testing.T) {
	t.Parallel()

	var unset context.Context
	if got := DLPWarnContextFromCtx(unset); got != (DLPWarnContext{}) {
		t.Fatalf("nil context = %+v, want zero value", got)
	}
	if got := DLPWarnContextFromCtx(context.Background()); got != (DLPWarnContext{}) {
		t.Fatalf("unset context = %+v, want zero value", got)
	}
}

func TestBufferDLPWarningsReplayAndNestedScan(t *testing.T) {
	sc := MustNew(config.Defaults())
	t.Cleanup(sc.Close)
	var calls atomic.Int64
	wc := DLPWarnContext{RequestID: "request-fixture", Transport: "intercept"}
	sc.SetDLPWarnHook(func(ctx context.Context, name, _ string) {
		calls.Add(1)
		if got := DLPWarnContextFromCtx(ctx); got.RequestID != wc.RequestID || got.Transport != wc.Transport {
			t.Errorf("warning attribution changed: %+v", got)
		}
		if name == "outer" {
			sc.emitDLPWarns(ctx, []WarnMatch{{PatternName: "nested", Severity: "info"}})
		}
	})
	ctx, replay := BufferDLPWarnings(WithDLPWarnContext(t.Context(), wc))
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() { sc.emitDLPWarns(ctx, []WarnMatch{{PatternName: "outer", Severity: "info"}}) })
	}
	workers.Wait()
	if calls.Load() != 0 {
		t.Fatal("warning hook ran before request-thread replay")
	}
	replay()
	if calls.Load() != 8 {
		t.Fatalf("outer and nested warnings = %d, want 8", calls.Load())
	}
	replay()
	if calls.Load() != 8 {
		t.Fatal("replaying an empty buffer duplicated warnings")
	}
}

func TestBufferDLPWarningsNilContextAndCallbackPanic(t *testing.T) {
	sc := MustNew(config.Defaults())
	t.Cleanup(sc.Close)
	sc.SetDLPWarnHook(func(context.Context, string, string) { panic("callback fixture") })
	var unset context.Context
	ctx, replay := BufferDLPWarnings(unset)
	sc.emitDLPWarns(ctx, []WarnMatch{{PatternName: "fixture", Severity: "info"}})
	defer func() {
		if got := recover(); got != "callback fixture" {
			t.Fatalf("callback panic = %v", got)
		}
	}()
	replay()
}
