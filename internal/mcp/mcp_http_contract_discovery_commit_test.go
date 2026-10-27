// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestContractDiscoveryCanceledWhileWaitingToCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	state := newMCPListenerClientState("", "test")
	state.commitMu.Lock()
	unlock := true
	defer func() {
		if unlock {
			state.commitMu.Unlock()
		}
	}()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		discoveryList(w, ParseMCPFrame([]byte(`{"id":1}`)), headerStateDefs(headerStateSchema, "Echo input"), "")
	}))
	defer up.Close()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://proxy.vendor.example/", nil)
	req.Header = currentWireHeaders(methodToolsCall, "echo")
	opts := paramContractOpts(t)
	done := make(chan error, 1)
	go func() {
		done <- discoverMCPToolContract(mcpContractDiscoveryRequest{request: req, client: up.Client(), upstream: up.URL, opts: opts, state: state, log: io.Discard, tool: "echo"})
	}()
	testwait.For(t, 2*time.Second, func() bool {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		return strings.Contains(string(buf[:n]), "mcp.(*mcpListenerClientState).commitIfActive(")
	}, "discovery queued at structural commit")
	cancel()
	state.commitMu.Unlock()
	unlock = false
	err := <-done
	if !errors.Is(err, context.Canceled) || state.baseline.HeaderContract("echo").State != tools.HeaderContractUnknown {
		t.Fatalf("canceled discovery committed after wait: error=%v contract=%v", err, state.baseline.HeaderContract("echo").State)
	}
}
