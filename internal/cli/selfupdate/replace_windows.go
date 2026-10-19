// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/luckyPipewrench/pipelock/internal/termsafe"
)

// moveWithoutReplace uses MoveFileW's no-clobber contract, including on restore.
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefilew
func moveWithoutReplace(src, dst string) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	if err := windows.MoveFile(from, to); err != nil {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
	}
	return nil
}

func replaceBinary(tmpPath, target string) error {
	return replaceRunningBinary(tmpPath, target, replacementOps{move: moveWithoutReplace})
}

// acquireReplacementLock holds a stable file outside the recovery directory.
// CreateFileW with no sharing excludes other opens and deletion until close:
// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
// Never delete this file: changing its identity would split concurrent owners.
func acquireReplacementLock(target string) (func(), error) {
	path := target + replacementSuffix + ".lock"
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encoding self-update lock: %w", err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, fmt.Errorf("%w; retry after it finishes; original unchanged: %w", errReplacementBusy, err)
		}
		return nil, fmt.Errorf("opening self-update lock; original unchanged: %w", err)
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("opening self-update lock: invalid handle; original unchanged")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("checking self-update lock; original unchanged: %w", err)
		}
		return nil, errors.New("self-update lock is not a regular file; original unchanged")
	}
	return func() { _ = f.Close() }, nil
}

// CleanupOnStart removes only the recorded prior image of this executable.
// A locked image or unrecognized recovery state is retained with a warning.
func CleanupOnStart(stderr io.Writer) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err == nil {
		err = cleanupReplacement(exe, replacementOps{})
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Warning: self-update cleanup deferred: %s\n", termsafe.Escape(err.Error()))
	}
}
