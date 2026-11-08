// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testexec"
)

// runSignalProcess keeps diagnostics readable while the command is running.
// Its stdout pipe belongs to the test, so Wait cannot close it before a read.
type runSignalProcess struct {
	t       *testing.T
	cmd     *exec.Cmd
	mu      sync.Mutex
	stderr  bytes.Buffer
	done    chan struct{}
	waitErr error
}

func newRunSignalProcess(t *testing.T) *runSignalProcess {
	t.Helper()
	run := &runSignalProcess{t: t, done: make(chan struct{})}
	t.Cleanup(func() {
		if run.cmd != nil && run.cmd.Process != nil {
			_ = run.cmd.Process.Kill()
			<-run.done
		}
		if t.Failed() {
			t.Log(run.diagnostics())
		}
	})
	return run
}

func (r *runSignalProcess) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stderr.Write(p)
}

func (r *runSignalProcess) diagnostics() string {
	status := "not started"
	if r.cmd != nil && r.cmd.Process != nil {
		status = "running (exit status unavailable)"
		select {
		case <-r.done:
			status = fmt.Sprintf("%v (wait error=%v)", r.cmd.ProcessState, r.waitErr)
		default:
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("wrapper exit=%s; wrapper/stub stderr=%s", status, r.stderr.String())
}

func (r *runSignalProcess) fatalf(format string, args ...any) {
	r.t.Helper()
	r.t.Fatalf("%s; %s", fmt.Sprintf(format, args...), r.diagnostics())
}

func (r *runSignalProcess) start(cmd *exec.Cmd) *os.File {
	r.t.Helper()
	stdout, writer, err := os.Pipe()
	if err != nil {
		r.fatalf("stdout pipe: %v", err)
	}
	r.t.Cleanup(func() { _ = stdout.Close() })
	cmd.Stdout, cmd.Stderr = writer, r
	r.cmd = cmd
	err = cmd.Start()
	_ = writer.Close()
	if err != nil {
		r.fatalf("start wrapper: %v", err)
	}
	go func() {
		r.waitErr = cmd.Wait()
		close(r.done)
	}()
	return stdout
}

func TestRunForwardsSignalsAndWaitsForHarness(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signal syscall.Signal
		code   int
		launch bool
	}{
		{"term", syscall.SIGTERM, 143, false},
		{"interrupt", syscall.SIGINT, 130, false},
		{"term-harness-status", syscall.SIGTERM, 3, false},
		{"term-launch-window", syscall.SIGTERM, 143, true},
		{"interrupt-launch-window", syscall.SIGINT, 130, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			run := newRunSignalProcess(t)
			python, err := exec.LookPath("python3")
			if err != nil {
				run.fatalf("%v", err)
			}
			marker := filepath.Join(root, "stopped")
			release := newRunReleaseFIFO(t, root)
			harness := filepath.Join(root, "harness")
			testexec.WriteExecutable(t, harness, []byte("#!"+python+"\n"+`import os, signal, sys
from pathlib import Path

parent = os.getppid()
signals = {signal.SIGTERM, signal.SIGINT}
# Block before announcing readiness: the wrapper may forward immediately.
# sigwait keeps buffered I/O out of asynchronous Python signal handlers.
signal.pthread_sigmask(signal.SIG_BLOCK, signals)
for signum in signals:
    # Non-interactive bash starts background jobs with SIGINT ignored.
    signal.signal(signum, signal.SIG_DFL)
print(os.getpid(), sys.argv[0], flush=True)
if "HARNESS_READY" in os.environ:
    with open(os.environ["HARNESS_READY"], "w") as ready:
        ready.write("ready\n")
signum = signal.sigwait(signals)
# The wrapper and scratch binary must survive through report finalization.
assert os.getppid() == parent, "wrapper exited before finalization"
os.kill(parent, 0)
assert Path(sys.argv[0]).exists(), "scratch binary removed before finalization"
Path(os.environ["HARNESS_MARKER"]).write_text(str(signum))
release = os.open(os.environ["HARNESS_RELEASE"], os.O_RDWR)
print("started", flush=True)
assert os.read(release, 1) == b"x", "finalization release missing"
os.close(release)
if os.environ["HARNESS_CODE"] == "3":
    sys.exit(3)
signal.pthread_sigmask(signal.SIG_UNBLOCK, {signum})
os.kill(os.getpid(), signum)
`), 0o700)
			writeRunBuildStubs(t, root)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "./run.sh", filepath.Join(root, "out")) // #nosec G204 -- fixed launcher with isolated fixtures.
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "HARNESS_STUB="+harness, "HARNESS_MARKER="+marker, "HARNESS_CODE="+strconv.Itoa(tc.code), "HARNESS_RELEASE="+release, "TMPDIR="+root)
			if tc.launch {
				ready := filepath.Join(root, "ready")
				if err := syscall.Mkfifo(ready, 0o600); err != nil {
					run.fatalf("%v", err)
				}
				// Stop at the assignment with the harness ready to receive signals.
				startup := filepath.Join(root, "bash-startup")
				testexec.WriteExecutable(t, startup, []byte(`before_assignment() {
  if [[ $BASH_COMMAND == 'harness_pid=$!' ]]; then
    IFS= read -r ready < "$HARNESS_READY"
    kill -s "$LAUNCH_SIGNAL" "$$"
  fi
}
trap before_assignment DEBUG
`), 0o700)
				cmd.Env = append(cmd.Env, "BASH_ENV="+startup, "HARNESS_READY="+ready, "LAUNCH_SIGNAL="+strconv.Itoa(int(tc.signal)))
			}
			stdout := run.start(cmd)
			var pid int
			var binary string
			if _, err := fmt.Fscanln(stdout, &pid, &binary); err != nil {
				run.fatalf("%v", err)
			}
			child, err := os.FindProcess(pid)
			if err != nil {
				run.fatalf("%v", err)
			}
			defer func() { _ = child.Kill() }()
			stopCleanup := context.AfterFunc(ctx, func() { _ = child.Kill() })
			defer stopCleanup()
			if !tc.launch {
				if err := cmd.Process.Signal(tc.signal); err != nil {
					run.fatalf("%v", err)
				}
			}
			var started string
			if _, err := fmt.Fscanln(stdout, &started); err != nil || started != "started" {
				run.fatalf("harness did not begin finalization: marker=%q, error=%v", started, err)
			}
			if data, err := os.ReadFile(filepath.Clean(marker)); err != nil || string(data) != strconv.Itoa(int(tc.signal)) {
				run.fatalf("signal marker=%q, error=%v", data, err)
			}
			assertRunStillFinalizing(t, run, binary)
			releaseRunFixture(t, release)
			<-run.done
			err = run.waitErr
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != tc.code {
				run.fatalf("run.sh exit=%v, want %d", err, tc.code)
			}
			if data, err := os.ReadFile(filepath.Clean(marker)); err != nil || string(data) != strconv.Itoa(int(tc.signal)) {
				run.fatalf("harness did not finalize before wrapper exit: marker=%q, error=%v", data, err)
			}
			if err := child.Signal(syscall.Signal(0)); !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
				run.fatalf("harness still running after wrapper exit: %v", err)
			}
			if paths, err := filepath.Glob(filepath.Join(root, "receipt-load.*")); err != nil || len(paths) != 0 {
				run.fatalf("scratch cleanup: paths=%v, error=%v", paths, err)
			}
		})
	}
}

// Keep finalization blocked long enough to observe a wrapper that abandons wait.
func assertRunStillFinalizing(t *testing.T, run *runSignalProcess, binary string) {
	t.Helper()
	observation := time.NewTimer(250 * time.Millisecond)
	defer observation.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-run.done:
			run.fatalf("wrapper exited before harness release: %v", run.waitErr)
		case <-poll.C:
			if err := run.cmd.Process.Signal(syscall.Signal(0)); err != nil {
				run.fatalf("wrapper did not survive finalization: %v", err)
			}
			if _, err := os.Stat(filepath.Clean(binary)); err != nil {
				run.fatalf("scratch binary removed before harness release: %v", err)
			}
		case <-observation.C:
			return
		}
	}
}

func newRunReleaseFIFO(t *testing.T, root string) string {
	t.Helper()
	release := filepath.Join(root, "release")
	if err := syscall.Mkfifo(release, 0o600); err != nil {
		t.Fatal(err)
	}
	return release
}

func releaseRunFixture(t *testing.T, path string) {
	t.Helper()
	// RDWR avoids blocking forever if a broken wrapper has already killed its child.
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
}

func TestRunCancellationDuringBuild(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signal syscall.Signal
		code   int
	}{
		{"term", syscall.SIGTERM, 143},
		{"interrupt", syscall.SIGINT, 130},
	} {
		t.Run(tc.name, func(t *testing.T) {
			python, err := exec.LookPath("python3")
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			release := newRunReleaseFIFO(t, root)
			marker := filepath.Join(root, "harness-started")
			harness := filepath.Join(root, "harness")
			testexec.WriteExecutable(t, harness, []byte("#!/bin/sh\nprintf ran >\"$HARNESS_MARKER\"\n"), 0o700)
			writeRunBuildStubs(t, root)
			testexec.WriteExecutable(t, filepath.Join(root, "go"), []byte("#!"+python+"\n"+`import os, shutil, sys
shutil.copyfile(os.environ["HARNESS_STUB"], sys.argv[3])
os.chmod(sys.argv[3], 0o700)
release = os.open(os.environ["BUILD_RELEASE"], os.O_RDWR)
print(os.getpid(), sys.argv[3], flush=True)
assert os.read(release, 1) == b"x"
os.close(release)
`), 0o700)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "./run.sh", filepath.Join(root, "out")) // #nosec G204 -- fixed launcher with isolated build fixture.
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "HARNESS_STUB="+harness, "HARNESS_MARKER="+marker, "BUILD_RELEASE="+release, "TMPDIR="+root)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			var pid int
			var binary string
			if _, err := fmt.Fscanln(stdout, &pid, &binary); err != nil {
				t.Fatal(err)
			}
			build, err := os.FindProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = build.Kill() }()
			stopCleanup := context.AfterFunc(ctx, func() { _ = build.Kill() })
			defer stopCleanup()
			if _, err := os.Stat(filepath.Clean(binary)); err != nil {
				t.Fatalf("build scratch missing: %v", err)
			}
			if err := cmd.Process.Signal(tc.signal); err != nil {
				t.Fatal(err)
			}
			releaseRunFixture(t, release)
			err = cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != tc.code {
				t.Fatalf("run.sh exit=%v, want %d; stderr=%s", err, tc.code, stderr.String())
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("harness started after build cancellation: %v", err)
			}
			if paths, err := filepath.Glob(filepath.Join(root, "receipt-load.*")); err != nil || len(paths) != 0 {
				t.Fatalf("scratch cleanup: paths=%v, error=%v", paths, err)
			}
		})
	}
}
