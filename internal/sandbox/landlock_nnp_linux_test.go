// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	landlockNNPOp              = "no-new-privs-all-threads"
	landlockNNPReportOp        = "no-new-privs-report"
	landlockNNPInheritedExit   = 3
	landlockNNPUnavailableExit = 4
	landlockNNPThreads         = 8
)

// runLandlockNoNewPrivsChild proves that ApplyLandlock alone leaves
// no_new_privs on every existing thread. Builds without Pipelock's seccomp
// filter, such as linux/arm64, have no other launcher step that sets it, and
// standalone mode starts the workload from an arbitrary Go thread.
func runLandlockNoNewPrivsChild(workspace string) {
	readNNP := func() int {
		nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "read no_new_privs: %v\n", err)
			os.Exit(2)
		}
		return nnp
	}
	runtime.LockOSThread()
	if readNNP() != 0 {
		_, _ = fmt.Fprintln(os.Stdout, "inherited no_new_privs cannot show the transition")
		os.Exit(landlockNNPInheritedExit)
	}

	type observation struct{ tid, before, after int }
	release := make(chan struct{})
	parked := make(chan observation, landlockNNPThreads)
	done := make(chan observation, landlockNNPThreads)
	for range landlockNNPThreads {
		go func() {
			// Never unlocked: the thread exits with this goroutine.
			runtime.LockOSThread()
			seen := observation{tid: unix.Gettid(), before: readNNP()}
			parked <- seen
			<-release
			seen.after = readNNP()
			done <- seen
		}()
	}
	tids := map[int]bool{unix.Gettid(): true}
	for range landlockNNPThreads {
		seen := <-parked
		if seen.before != 0 {
			_, _ = fmt.Fprintf(os.Stderr, "thread %d had no_new_privs before landlock\n", seen.tid)
			os.Exit(2)
		}
		tids[seen.tid] = true
	}
	if len(tids) != landlockNNPThreads+1 {
		_, _ = fmt.Fprintf(os.Stderr, "parked %d distinct threads, want %d\n", len(tids), landlockNNPThreads+1)
		os.Exit(2)
	}

	self, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "test binary: %v\n", err)
		os.Exit(2)
	}
	policy := DefaultPolicy(workspace)
	policy.AllowReadDirs = append(policy.AllowReadDirs, filepath.Dir(self))
	// A coverage build writes counters at exit from this child and from the
	// re-exec'd workload; both run inside the domain.
	if dir := os.Getenv("GOCOVERDIR"); dir != "" {
		policy.AllowRWDirs = append(policy.AllowRWDirs, filepath.Clean(dir))
	}
	status, err := ApplyLandlock(policy)
	if errors.Is(err, ErrUnavailable) {
		_, _ = fmt.Fprintf(os.Stderr, "landlock unavailable: %s\n", status.Reason)
		os.Exit(landlockNNPUnavailableExit)
	}
	if err != nil || !status.Active {
		_, _ = fmt.Fprintf(os.Stderr, "landlock: active=%v err=%v reason=%s\n", status.Active, err, status.Reason)
		os.Exit(2)
	}
	close(release)
	if readNNP() != 1 {
		_, _ = fmt.Fprintln(os.Stderr, "landlock thread lacks no_new_privs")
		os.Exit(1)
	}
	for range landlockNNPThreads {
		if seen := <-done; seen.after != 1 {
			_, _ = fmt.Fprintf(os.Stderr, "pre-existing thread %d lacks no_new_privs after landlock\n", seen.tid)
			os.Exit(1)
		}
	}
	runtime.UnlockOSThread()

	// Like the standalone launcher, start the workload from an unpinned goroutine.
	result := make(chan string, 1)
	go func() {
		cmd := exec.CommandContext(context.Background(), self, "-test.run=^$") // #nosec G204 G702 -- re-exec of this test binary
		cmd.Env = append(os.Environ(), landlockTestEnv+"="+landlockNNPReportOp)
		out, err := cmd.CombinedOutput()
		if err != nil {
			result <- fmt.Sprintf("workload: %v: %s", err, out)
			return
		}
		result <- strings.TrimSpace(string(out))
	}()
	if workload := <-result; workload != "no_new_privs=1" {
		_, _ = fmt.Fprintf(os.Stderr, "workload reported %q, want no_new_privs=1\n", workload)
		os.Exit(1)
	}
	_, _ = fmt.Fprintf(os.Stdout, "no_new_privs on %d threads and the workload\n", len(tids))
	os.Exit(0)
}

func TestApplyLandlock_SetsNoNewPrivsOnEveryThread(t *testing.T) {
	out, code := runSandboxedChild(t, landlockNNPOp, t.TempDir())
	if code == landlockNNPInheritedExit || code == landlockNNPUnavailableExit {
		t.Skip(strings.TrimSpace(out))
	}
	want := fmt.Sprintf("no_new_privs on %d threads and the workload", landlockNNPThreads+1)
	if code != 0 || strings.TrimSpace(out) != want {
		t.Fatalf("landlock no_new_privs proof exited %d: %s", code, out)
	}
}

// reportNoNewPrivs is the workload started by runLandlockNoNewPrivsChild.
func reportNoNewPrivs() {
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "read no_new_privs: %v\n", err)
		os.Exit(2)
	}
	_, _ = fmt.Fprintf(os.Stdout, "no_new_privs=%d\n", nnp)
	os.Exit(0)
}
