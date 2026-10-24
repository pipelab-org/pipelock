// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtimeconfig

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/diaglog"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMCPTaintDiagnostics_OnlySessionModes(t *testing.T) {
	for _, mode := range []config.RuntimeMode{config.RuntimeForward, config.RuntimeForwardWithMCPListener, config.RuntimeMCPProxy, config.RuntimeMCPScan} {
		var log bytes.Buffer
		w := diaglog.New(&log)
		ResolveAndReportConfig(config.Defaults(), config.RuntimeResolveOpts{Mode: mode}, w, "test")
		if done := w.Pending(); done != nil {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("diagnostic did not finish")
			}
		}
		if got := strings.Contains(log.String(), "taint.mcp_listener:"); got != mode.WrapsMCP() {
			t.Fatalf("mode %v diagnostic=%t", mode, got)
		}
	}
	EmitMCPTaintDiagnostics(nil, nil, config.RuntimeMCPProxy)
}

// Config resolution must finish even if the optional startup diagnostic cannot
// reach its operator sink. Ordinary warnings use the same shared writer.
func TestMCPTaintDiagnostics_StartupDoesNotWaitForSink(t *testing.T) {
	sink := &blockedTaintConfigWriter{entered: make(chan struct{}), release: make(chan struct{})}
	w := diaglog.New(sink)
	defer func() {
		close(sink.release)
		if done := w.Pending(); done != nil {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("diagnostic cleanup stalled")
			}
		}
	}()
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		ResolveAndReportConfig(config.Defaults(), config.RuntimeResolveOpts{Mode: config.RuntimeMCPProxy}, w, "proxy")
	}()
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("startup resolution held by diagnostic I/O")
	}
	select {
	case <-sink.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("startup diagnostic was not submitted")
	}
	if RenderMCPTaintDiagnostics(nil, config.RuntimeMCPProxy) != "" {
		t.Fatal("nil configuration rendered diagnostic")
	}
}

type blockedTaintConfigWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockedTaintConfigWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "pipelock: diagnostic:") {
		w.once.Do(func() { close(w.entered) })
		<-w.release
	}
	return len(p), nil
}
