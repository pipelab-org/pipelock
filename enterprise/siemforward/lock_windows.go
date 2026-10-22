//go:build enterprise && windows

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package siemforward

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// acquireStateLock takes an exclusive lock on a sidecar lock file so a second
// process cannot deliver against the same spool and cursor. The lock is held
// for the forwarder's lifetime and released by releaseStateLock on Close.
func acquireStateLock(spoolPath string) (*os.File, error) {
	lockPath := filepath.Clean(spoolPath + ".lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open siem forwarder lock file %q: %w", lockPath, err)
	}
	overlapped := new(windows.Overlapped)
	err = windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, overlapped,
	)
	if err != nil {
		_ = file.Close()
		return nil, stateLockError(spoolPath, err)
	}
	return file, nil
}

func stateLockError(spoolPath string, err error) error {
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return fmt.Errorf("siem forwarder spool %q is locked by another Pipelock process; give each process its own emit.forwarder.spool_file and emit.forwarder.cursor_file pair: %w", spoolPath, err)
	}
	return fmt.Errorf("lock siem forwarder spool %q: %w", spoolPath, err)
}

// releaseStateLock unlocks and closes the lock file. Safe to call with nil.
func releaseStateLock(file *os.File) {
	if file == nil {
		return
	}
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, new(windows.Overlapped))
	_ = file.Close()
}
