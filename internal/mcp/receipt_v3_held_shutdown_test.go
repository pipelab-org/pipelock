// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type observedFileWriter struct {
	*os.File
	entered chan struct{}
}

func (w observedFileWriter) Write(p []byte) (int, error) {
	close(w.entered)
	return w.File.Write(p)
}

func TestMCPV3BridgeShutdownInterruptsHeldReply(t *testing.T) {
	opts, writer, observer := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPHTTPUpstream)
	fixture := nativeDeferredOptions(t, nil)
	opts.Scanner, opts.InputCfg = fixture.Scanner, fixture.InputCfg
	opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Minute})
	opts.ListenerShutdownTimeout = 50 * time.Millisecond
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, heldNativeReply)
	}))
	defer upstream.Close()
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = readEnd.Close() }()
	defer func() { _ = writeEnd.Close() }()
	if err := writeEnd.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Skipf("pipe write deadlines unavailable: %v", err)
	}
	if _, err := writeEnd.Write(make([]byte, 1<<20)); !os.IsTimeout(err) {
		t.Fatalf("fill pipe: %v", err)
	}
	if err := writeEnd.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
	defer cancel()
	in, input := io.Pipe()
	defer func() { _ = in.Close(); _ = input.Close() }()
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPProxy(ctx, in, observedFileWriter{File: writeEnd, entered: entered}, io.Discard, upstream.URL, nil, opts)
	}()
	if _, err := io.WriteString(input, heldNativeCall+"\n"); err != nil {
		t.Fatal(err)
	}
	testwait.ForContext(t, ctx, func() bool { return opts.DeferManager.HeldCount() == 1 }, "confirmed hold")
	resolved := make(chan error, 1)
	go func() {
		resolved <- opts.DeferManager.Resolve(opts.DeferManager.Snapshot()[0].DeferID, config.ActionAllow, deferred.SourceApproval)
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("held reply did not start writing")
	}
	_ = input.Close()
	shutdown := time.NewTimer(testwait.Deadline(time.Second))
	defer shutdown.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-shutdown.C:
		_ = writeEnd.SetWriteDeadline(time.Now())
		proxyErr := <-done
		resolveErr := <-resolved
		t.Fatalf("bridge did not interrupt held reply: proxy=%v resolution=%v", proxyErr, resolveErr)
	}
	if err := <-resolved; err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, action := range localMCPReceiptActions(t, writer, observer.dir) {
		if action.EffectBoundary == mcpDownstreamDeliveryBoundary && action.Phase == "outcome" {
			outcomes = append(outcomes, action.OutcomeClass)
		}
	}
	if !slices.Equal(outcomes, []string{"attempt_unknown"}) {
		t.Fatalf("interrupted delivery outcomes = %v", outcomes)
	}
}
