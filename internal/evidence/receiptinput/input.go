// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

// Package receiptinput protects legacy evidence readers from unsupported receipt formats.
package receiptinput

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
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
	claimed, err = ClaimsInput(path, info.IsDir())
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
		if err := evidencename.RefuseReceiptContent(line); err != nil {
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
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return Refuse(dir, command, reader)
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}

	// Match the recorder's directory read ceiling and the evidence doctor's
	// corpus file budget. This is a preflight for legacy readers, not a census.
	const maxDirectories = recorder.MaxEvidenceReadDirectoryEntries
	const maxEntries = 16 * recorder.MaxEvidenceReadDirectoryEntries
	remainingEntries := maxEntries
	pending := []string{root}
	for visited := 0; len(pending) != 0; visited++ {
		if visited == maxDirectories {
			return treeLimit(command, reader, maxDirectories, "directories")
		}
		path := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		entries, err := readTreeDirectory(path, remainingEntries+1)
		if err != nil {
			return err
		}
		if len(entries) > remainingEntries {
			return treeLimit(command, reader, maxEntries, "entries")
		}
		remainingEntries -= len(entries)
		claimed, err := ClaimsDirectory(path, entries)
		if claimed {
			return unsupported(command, reader, true)
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := entry.Name()
			switch {
			case entry.IsDir():
				pending = append(pending, filepath.Join(path, name))
			case entry.Type().IsRegular() && !evidencename.IsLegacyReceiptCandidate(name) &&
				slices.ContainsFunc(extraCandidates, func(matches func(string) bool) bool { return matches(name) }):
				if err := Refuse(filepath.Join(path, name), command, reader); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func readTreeDirectory(path string, limit int) ([]fs.DirEntry, error) {
	dir, err := recorder.OpenEvidenceDirectory(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(limit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return entries, nil
}

func treeLimit(command, reader string, limit int, unit string) error {
	return fmt.Errorf("%s: %s: %w (%d %s); use 'pipelock verify-receipt --chain <dir>'",
		command, reader, recorder.ErrEvidenceReadLimitExceeded, limit, unit)
}
