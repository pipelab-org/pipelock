// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
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
	writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPHTTPUpstream)
	opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer)
	opts.Transport = deferred.SurfaceMCPHTTPUpstream
	opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Minute})
	opts.ListenerShutdownTimeout = 50 * time.Millisecond
	sends := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		sends <- msg
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
	held := opts.DeferManager.Snapshot()[0]
	resolved := make(chan error, 1)
	go func() {
		resolved <- opts.DeferManager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval)
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
	if sent := awaitHeldTest(t, sends); !bytes.Equal(sent, []byte(heldNativeCall)) {
		t.Fatalf("upstream observed %q", sent)
	}
	actions := verifiedMCPV3RegressionActions(t, writer, writerOpts)
	want := []heldEvidencePoint{holdPoint(held.ActionID, ""), resolutionPoint(held.ActionID, config.ActionAllow, false)}
	assertHeldEvidence(t, actions, append(want, heldAttempt(held.ActionID, "completed")...))
	var replies []v3.Action
	for _, action := range actions {
		if action.EffectBoundary == mcpDownstreamDeliveryBoundary {
			replies = append(replies, action)
		}
	}
	if len(replies) != 2 || replies[0].Phase != "intent" || replies[1].Phase != "outcome" ||
		replies[0].ActionID != replies[1].ActionID || replies[0].ParentActionID != held.ActionID ||
		replies[1].ParentActionID != held.ActionID || replies[0].RequestID != "1" || replies[1].RequestID != "1" ||
		replies[1].OutcomeClass != "attempt_unknown" {
		t.Fatalf("interrupted delivery evidence = %+v", replies)
	}
}
