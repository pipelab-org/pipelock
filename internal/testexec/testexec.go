// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package testexec writes executable test fixtures that are safe to run
// while other tests start processes in parallel.
//
// A file written with os.WriteFile can fail to execute with "text file
// busy" (ETXTBSY) when another goroutine forks between the open and the
// close of the file: the child briefly inherits the write descriptor, and
// the kernel refuses to exec a file that is open for writing. Holding
// syscall.ForkLock for the whole write blocks those forks
// (https://go.dev/issue/22315).
package testexec

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// WriteExecutable writes data to path with perm and closes it while no
// process can be forked, so the file can be executed right away. It ends
// the test on failure.
func WriteExecutable(tb testing.TB, path string, data []byte, perm os.FileMode) {
	tb.Helper()
	if err := Write(path, data, perm); err != nil {
		tb.Fatalf("write executable %s: %v", path, err)
	}
}

// Write is WriteExecutable without a test handle, for helpers that return
// errors.
func Write(path string, data []byte, perm os.FileMode) (err error) {
	syscall.ForkLock.Lock()
	defer syscall.ForkLock.Unlock()

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) // #nosec G302 G304 -- caller-owned test fixture path and mode.
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Chmod(perm)
}
