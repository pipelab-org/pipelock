// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package receiptinput

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// ClaimsInput reports whether a file or directory is claimed by the receipt
// profile verifier: a profile stream name, or a legacy candidate whose content
// begins with the profile prefix. This is the one definition of the claim rule.
// It lives here, not in the verifier, so that js/wasm builds, which cannot link
// the verifier's SQLite driver, can still refuse a claimed input.
func ClaimsInput(path string, directory bool) (bool, error) {
	if directory {
		dir, entries, err := readClaimDirectory(path)
		if err != nil {
			return false, err
		}
		return ClaimsDirectory(dir, entries)
	}
	if evidencename.ClaimsReceiptName(filepath.Base(path)) {
		return true, nil
	}
	return claimsFileContent(path)
}

// ClaimsDirectory applies the claim rule to a listing the caller already read.
func ClaimsDirectory(dir string, entries []os.DirEntry) (bool, error) {
	if evidencename.ReceiptProfileEntry(entries) != "" {
		return true, nil
	}
	var probeErr error
	for _, entry := range entries {
		if !entry.IsDir() && evidencename.IsLegacyReceiptCandidate(entry.Name()) && entry.Type().IsRegular() {
			claimed, err := claimsFileContent(filepath.Join(dir, entry.Name()))
			if claimed {
				return true, nil
			}
			if probeErr == nil {
				probeErr = err
			}
		}
	}
	return false, probeErr
}

func claimsFileContent(path string) (bool, error) {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, fmt.Errorf("open evidence file: resolve evidence path: %w", err)
	}
	file, _, err := recorder.OpenEvidenceFile(realPath)
	if err != nil {
		return false, fmt.Errorf("open evidence file: open evidence: %w", err)
	}
	defer func() { _ = file.Close() }()
	return evidencename.ProbeReceiptContent(file)
}

func readClaimDirectory(path string) (string, []os.DirEntry, error) {
	dir, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve evidence directory: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, fmt.Errorf("read evidence directory: %w", err)
	}
	return dir, entries, nil
}
