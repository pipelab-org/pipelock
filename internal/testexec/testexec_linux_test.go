// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package testexec_test

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testexec"
)

// TestWriteExecutableRunsWhileOtherTestsFork writes and runs fresh scripts
// while other goroutines keep forking. A plain os.WriteFile fails here with
// "text file busy" whenever a fork lands between its open and close.
func TestWriteExecutableRunsWhileOtherTestsFork(t *testing.T) {
	t.Parallel()

	const (
		forkers    = 4
		iterations = 200
	)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range forkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = exec.Command("/bin/true").Run()
			}
		}()
	}
	defer func() {
		close(stop)
		wg.Wait()
	}()

	dir := t.TempDir()
	for i := range iterations {
		path := filepath.Join(dir, "probe-"+strconv.Itoa(i))
		testexec.WriteExecutable(t, path, []byte("#!/bin/sh\nexit 0\n"), 0o700)
		if out, err := exec.Command(path).CombinedOutput(); err != nil { // #nosec G204 -- test-owned fixture path.
			t.Fatalf("iteration %d: run %s: %v: %s", i, path, err, out)
		}
	}
}
