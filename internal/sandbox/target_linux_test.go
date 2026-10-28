// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSandboxTargetSignals(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL} {
		t.Run(sig.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sleep", "60")
			target, err := startSandboxTarget(cmd, LayerStatus{Active: true, Version: 9})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			defer func() { _ = target.Signal(os.Kill); _ = cmd.Wait() }()
			if err := target.Signal(syscall.Signal(-1)); err == nil {
				t.Fatal("invalid signal accepted")
			}
			if err := target.Signal(sig); err != nil {
				t.Fatal(err)
			}
			var exitErr *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exitErr) {
				t.Fatalf("Wait = %v", err)
			}
			if status := exitErr.Sys().(syscall.WaitStatus); !status.Signaled() || status.Signal() != sig {
				t.Fatalf("status = %v, want signal %v", status, sig)
			}
			// Closing and signaling concurrently must neither strand a sender nor
			// leave the dedicated thread alive after Close returns.
			var group sync.WaitGroup
			for range 4 {
				group.Go(func() { target.Close() })
				group.Go(func() {
					if err := target.Signal(sig); !errors.Is(err, os.ErrProcessDone) {
						t.Errorf("post-Wait signal = %v", err)
					}
				})
			}
			group.Wait()
		})
	}
}

func TestSandboxTargetContextCancellation(t *testing.T) {
	const helperEnv = "PIPELOCK_TEST_TARGET_CANCEL"
	if os.Getenv(helperEnv) == "" {
		if Detect().LandlockABI < 6 {
			t.Skip("signal scopes require Landlock ABI 6")
		}
		workspace := t.TempDir()
		denied := filepath.Join(t.TempDir(), "denied")
		if err := os.WriteFile(denied, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), landlockChildTimeout)
		defer cancel()
		helper := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSandboxTargetContextCancellation$", "-test.v") // #nosec G204 G702 -- re-exec this test binary with a fixed selector, no external command input.
		// Keep TestMain's temporary files inside the grant so it can clean
		// them after this subprocess permanently enters Landlock.
		helper.Env = append(os.Environ(), helperEnv+"="+workspace, "PIPELOCK_TEST_TARGET_DENIED="+denied, "TMPDIR="+workspace)
		helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		helper.Cancel = func() error { return killProcessGroup(helper.Process.Pid) }
		out, err := helper.CombinedOutput()
		if err != nil {
			t.Fatalf("confined cancellation: %v\n%s", err, out)
		}
		t.Logf("%s", out)
		return
	}
	workspace := os.Getenv(helperEnv)
	status, err := ApplyLandlock(DefaultPolicy(workspace))
	if err != nil || !status.Active {
		t.Fatalf("Landlock = %+v, %v", status, err)
	}
	t.Logf("active Landlock ABI %d", status.Version)
	if err := os.WriteFile(filepath.Join(workspace, "allowed"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(os.Getenv("PIPELOCK_TEST_TARGET_DENIED")); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("outside read = %v, want permission denial", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sleep", "60")
	target, err := startSandboxTarget(cmd, status)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatalf("cancel result = %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = target.Signal(os.Kill)
		err := <-done
		t.Fatalf("context cancellation did not kill target; cleanup wait: %v", err)
	}
}

func TestSandboxTargetStartFailure(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		cmd := exec.CommandContext(ctx, "/nonexistent/sandbox-test-target")
		target, err := startSandboxTarget(cmd, LayerStatus{Active: true, Version: 9})
		cancel()
		if err == nil || target != nil {
			t.Fatalf("failed start = %v, %v", target, err)
		}
	}
}
