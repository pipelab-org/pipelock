// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

// Package receiptinput protects legacy evidence readers from unsupported receipt formats.
package receiptinput

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// ErrUnsupported marks a refusal from a reader without v3 support.
var ErrUnsupported = evidencename.ErrReceiptProfile

// Claims reports whether path is a file or directory claimed by the v3 verifier.
func Claims(path string) (bool, error) {
	claimed, _, err := inspect(path)
	return claimed, err
}

func inspect(path string) (claimed, directory bool, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, false, err
	}
	claimed, err = v3.ClaimsInput(path, info.IsDir())
	return claimed, info.IsDir(), err
}

// Refuse rejects a v3 claim before a legacy reader opens or selects evidence.
func Refuse(path, command, reader string) error {
	claimed, directory, err := inspect(path)
	if err != nil {
		return err
	}
	if claimed {
		return unsupported(command, reader, directory)
	}
	return nil
}

// UnsupportedDirectory is the refusal for a directory known to hold v3.
func UnsupportedDirectory(command, reader string) error {
	return unsupported(command, reader, true)
}

func unsupported(command, reader string, directory bool) error {
	verify := "pipelock verify-receipt <path>"
	if directory {
		verify = "pipelock verify-receipt --chain <path>"
	}
	return fmt.Errorf("%s: %w by %s in this release; use '%s'", command, ErrUnsupported, reader, verify)
}

// RefusePayload applies the v3 content rule where evidence arrives as bytes.
func RefusePayload(payload []byte, command, reader string) error {
	for remaining := payload; len(remaining) > 0; {
		line := remaining
		if nl := bytes.IndexByte(remaining, '\n'); nl >= 0 {
			line = remaining[:nl]
			remaining = remaining[nl+1:]
		} else {
			remaining = nil
		}
		if evidencename.ClaimsReceiptContent(line) {
			return unsupported(command, reader, false)
		}
	}
	return nil
}

// RefuseLocation rejects v3 claims at dir or in any non-symlink descendant
// directory under dir, preserving the claimed filename when recorder discovery
// identifies one.
func RefuseLocation(dir, command, reader string) error {
	if err := Refuse(dir, command, reader); err != nil {
		return err
	}
	if _, err := recorder.DiscoverEvidenceLocations(dir); errors.Is(err, recorder.ErrLegacyEvidenceFormat) {
		var claimed *fs.PathError
		if errors.As(err, &claimed) {
			return fmt.Errorf("%w (found %q)", unsupported(command, reader, true), claimed.Path)
		}
		return unsupported(command, reader, true)
	}
	return RefuseTree(dir, command, reader)
}

// RefuseTree rejects a directory when it or any non-symlink descendant
// directory holds v3 evidence. A reader can supply additional filenames it
// treats as evidence even when the standard directory probe does not.
func RefuseTree(dir, command, reader string, extraCandidates ...func(string) bool) error {
	claimed, directory, err := inspect(dir)
	if err != nil {
		return err
	}
	if claimed {
		return unsupported(command, reader, directory)
	}
	if !directory {
		return nil
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			name := entry.Name()
			if entry.Type().IsRegular() && !evidencename.IsLegacyReceiptCandidate(name) &&
				slices.ContainsFunc(extraCandidates, func(matches func(string) bool) bool { return matches(name) }) {
				return Refuse(path, command, reader)
			}
			return nil
		}
		if path == root {
			return nil
		}
		claimed, checkErr := v3.ClaimsInput(path, true)
		if checkErr != nil {
			return checkErr
		}
		if claimed {
			return unsupported(command, reader, true)
		}
		return nil
	})
}
