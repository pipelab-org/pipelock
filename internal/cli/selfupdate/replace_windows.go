// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
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
