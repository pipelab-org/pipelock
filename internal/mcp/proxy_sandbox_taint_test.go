// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSandboxProxyUsesInvocationRecorder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sandbox subprocess fixture requires /bin/echo")
	}
	for _, tc := range []struct {
		name      string
		external  bool
		fromStore bool
		level     session.TaintLevel
	}{
		{name: "external", external: true, level: session.TaintExternalUntrusted},
		{name: "undeclared", level: session.TaintInternalGenerated},
		{name: "store_owned", external: true, fromStore: true, level: session.TaintExternalUntrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &taintRecorder{}
			var output, logs bytes.Buffer
			cmd := exec.CommandContext(t.Context(), "/bin/echo", cleanResponse)
			opts := MCPProxyOpts{
				Scanner: testScannerWithAction(t, config.ActionWarn), Rec: rec,
				TaintCfg: &cfg.Taint, TaintExternalSource: tc.external,
			}
			if tc.fromStore {
				opts.Rec = nil
				opts.Store = findingRecorderStore{rec: rec}
			}
			err := RunProxyWithSandbox(t.Context(), cmd, strings.NewReader(""), &output, &logs, opts)
			if err != nil {
				t.Fatalf("sandbox proxy: %v; logs=%s", err, &logs)
			}
			if got := rec.RiskSnapshot().Level; got != tc.level {
				t.Fatalf("invocation recorder level=%s want=%s; output=%s", got, tc.level, &output)
			}
		})
	}
}

func TestAcquireSandboxRecorderCapacityDenial(t *testing.T) {
	for _, throughProxy := range []bool{false, true} {
		t.Run(map[bool]string{false: "bridge_allocation", true: "sandbox_proxy"}[throughProxy], func(t *testing.T) {
			logger, events := newListenerEventLogger(t)
			opts := MCPProxyOpts{Store: &capacityTestStore{}, AuditLogger: logger}
			var err error
			if throughProxy {
				started := false
				err = runProxyWithSandbox(t.Context(), &exec.Cmd{}, func() error { started = true; return nil }, strings.NewReader(""), io.Discard, io.Discard, opts)
				if started {
					t.Fatal("child started after capacity refusal")
				}
			} else {
				var release func()
				opts, release, err = AcquireSandboxRecorder(opts)
				release()
				if opts.Rec != nil {
					t.Fatal("recorder returned after capacity refusal")
				}
			}
			if !errors.Is(err, session.ErrCapacity) {
				t.Fatalf("err=%v, want capacity refusal", err)
			}
			assertDenialRoute(t, events.String(), scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceStartup, "startup")
			t.Logf("capacity refusal recorded exactly one protective startup denial")
		})
	}
}

func TestAcquireSandboxRecorderLifecycle(t *testing.T) {
	for _, mode := range []string{"no_store", "store_owned", "caller_owned"} {
		t.Run(mode, func(t *testing.T) {
			store := &capacityTestStore{rec: &mockRecorder{}}
			opts := MCPProxyOpts{}
			if mode != "no_store" {
				opts.Store = store
			}
			if mode == "caller_owned" {
				opts.Rec = store.rec
			}
			acquired, release, err := AcquireSandboxRecorder(opts)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "no_store" && (acquired.Rec != store.rec || acquired.taskSubject == "") {
				t.Fatalf("lost recorder or task subject: %+v", acquired)
			}
			again, releaseAgain, err := AcquireSandboxRecorder(acquired)
			if err != nil {
				t.Fatal(err)
			}
			if again.Rec != acquired.Rec || again.taskSubject != acquired.taskSubject {
				t.Fatal("recorder or task subject changed on reuse")
			}
			releaseAgain()
			if store.deletedKey != "" {
				t.Fatal("borrower deleted the invocation")
			}
			release()
			if mode == "store_owned" {
				if store.deletedKey == "" || store.deletedKey != store.admittedKey || acquired.taskSubject != store.admittedKey {
					t.Fatalf("allocation/release mismatch: %+v", store)
				}
			} else if store.admittedKey != "" || store.deletedKey != "" {
				t.Fatalf("caller-owned invocation mutated store: %+v", store)
			}
		})
	}
}

type boundSubjectRecorder struct {
	mockRecorder
	subject string
}

func (r *boundSubjectRecorder) TaskSubject() string { return r.subject }

func TestAcquireSandboxRecorderAdoptsBoundSubject(t *testing.T) {
	rec := &boundSubjectRecorder{subject: "caller-bound"}
	acquired, release, err := AcquireSandboxRecorder(MCPProxyOpts{Rec: rec})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if acquired.taskSubject != "caller-bound" {
		t.Fatalf("task subject=%q, want the recorder's bound subject", acquired.taskSubject)
	}
}
