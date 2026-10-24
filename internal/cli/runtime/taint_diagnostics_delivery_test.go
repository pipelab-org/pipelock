// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/diaglog"
)

type taintStartupWarningSink struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (s *taintStartupWarningSink) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "pipelock: diagnostic:") {
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *taintStartupWarningSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestMCPProxyTaintDiagnostics_DegradedWarningSurvivesSlowDiagnostic(t *testing.T) {
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "rules", "pipelock-standard")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), []byte("name: pipelock-standard\nversion: 2026.01.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\nrules:\n  rules_dir: "+filepath.Join(dir, "rules")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop before launch")
	var auditStream io.Writer
	factory := func(_ string, output, _ string, _, _ bool, stream io.Writer) (*audit.Logger, error) {
		auditStream = stream
		if output != "stdout" {
			t.Errorf("default audit output=%q", output)
		}
		return nil, stop
	}
	cmd := mcpCmdWithAuditLoggerFactory(factory)
	sink := &taintStartupWarningSink{entered: make(chan struct{}), release: make(chan struct{})}
	cmd.SetErr(sink)
	cmd.SetOut(io.Discard)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"proxy", "--config", cfgPath, "--", "unused-command"})
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()
	released := false
	finished := false
	defer func() {
		if !released {
			close(sink.release)
		}
		waitRuntimeTaintDiagnostic(t, diaglog.New(cmd.ErrOrStderr()))
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("startup cleanup stalled")
			}
		}
	}()
	select {
	case <-sink.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("config diagnostic did not reach sink")
	}
	select {
	case err := <-done:
		finished = true
		t.Fatalf("ordinary startup output falsely completed before sink recovered: %v\n%s", err, sink.String())
	case <-time.After(50 * time.Millisecond):
	}
	close(sink.release)
	released = true
	select {
	case err := <-done:
		finished = true
		if !errors.Is(err, stop) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not resume")
	}
	if _, ok := auditStream.(*diaglog.Writer); !ok {
		t.Fatalf("default audit stream does not share log owner: %T", auditStream)
	}
	if got := strings.Count(sink.String(), "DEGRADED"); got != 1 || !strings.Contains(sink.String(), "running core patterns only") {
		t.Fatalf("degraded warning lost: %s", sink.String())
	}
}
