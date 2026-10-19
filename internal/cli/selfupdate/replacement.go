// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

// The recovery directory is reserved exclusively by the replacement helper.
// Only these two files are owned. Never glob backups or recursively remove it.
const (
	replacementSuffix     = ".pipelock-update"
	priorImageName        = "previous.exe"
	replacementRecordName = "sha256"
)

var errReplacementBusy = errors.New("another self-update or cleanup is running")

// replacementOps exposes filesystem failures without process-global test hooks.
// move must refuse an existing destination; Windows supplies MoveFileW.
type replacementOps struct {
	move   func(string, string) error
	mkdir  func(string, os.FileMode) error
	write  func(string, []byte, os.FileMode) error
	remove func(string) error
	digest func(string) (string, error)
}

func (o replacementOps) defaults() replacementOps {
	if o.mkdir == nil {
		o.mkdir = os.Mkdir
	}
	if o.write == nil {
		o.write = atomicfile.WriteNew
	}
	if o.remove == nil {
		o.remove = os.Remove
	}
	if o.digest == nil {
		o.digest = binaryDigest
	}
	return o
}

func binaryDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a regular file", path)
	}
	in, err := os.Open(path) // #nosec G304 -- updater-owned executable or fixed recovery file
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	h := sha256.New()
	if err := copyBounded(h, in); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// replaceRunningBinary keeps the mapped image available under a private name.
// Windows cannot delete a mapped executable; rename aside avoids that delete.
// The two moves are not an atomic exchange. On second-move failure the first
// move is reversed without clobbering a concurrently created target. Production
// callers hold the replacement lock across backup and this entire operation.
func replaceRunningBinary(candidate, target string, ops replacementOps) error {
	ops = ops.defaults()
	next, err := ops.digest(candidate)
	if err != nil {
		return fmt.Errorf("checking replacement; original unchanged: %w", err)
	}
	original, err := ops.digest(target)
	if errors.Is(err, os.ErrNotExist) {
		if err := ops.move(candidate, target); err != nil {
			return fmt.Errorf("installing at missing target: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking original: %w", err)
	}
	dir := target + replacementSuffix
	if err := ops.mkdir(dir, 0o750); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Cleanup never removes state it cannot prove it owns, so this
			// stays blocked until the operator inspects it.
			return fmt.Errorf("recovery directory %q remains from an earlier update; original unchanged. "+
				"After confirming %q runs correctly, stop processes still running the previous executable, "+
				"then remove that directory and retry: %w", dir, target, err)
		}
		return fmt.Errorf("reserving recovery directory %q; original unchanged: %w", dir, err)
	}
	record := filepath.Join(dir, replacementRecordName)
	// Fixed record format: two lowercase SHA256 hex digests, each newline-ended.
	// The paths are fixed locally, never read from the record.
	if err := ops.write(record, []byte(original+"\n"+next+"\n"), 0o600); err != nil {
		if !errors.Is(err, os.ErrExist) {
			_ = ops.remove(record)
		}
		_ = ops.remove(dir)
		return fmt.Errorf("recording replacement; original unchanged: %w", err)
	}
	aside := filepath.Join(dir, priorImageName)
	if err := ops.move(target, aside); err != nil {
		// The directory may contain a colliding file. Remove only our record.
		_ = ops.remove(record)
		_ = ops.remove(dir)
		return fmt.Errorf("moving original aside (%s): %w", originalState(target, original, ops), err)
	}
	// Refuse to install if the source changed while it was being prepared.
	if got, hashErr := ops.digest(aside); hashErr != nil || got != original {
		return restorePriorImage(target, aside, original, ops, errors.New("saved original changed during replacement"))
	}
	if err := ops.move(candidate, target); err != nil {
		return restorePriorImage(target, aside, original, ops, err)
	}
	// The old image is still mapped by this process. Leave it for next startup.
	return nil
}

func originalState(target, original string, ops replacementOps) string {
	got, err := ops.digest(target)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "target missing"
	case err != nil:
		return "target state unknown"
	case got == original:
		return "original unchanged"
	default:
		return "target changed"
	}
}

func restorePriorImage(target, aside, original string, ops replacementOps, installErr error) error {
	if err := ops.move(aside, target); err != nil {
		return fmt.Errorf("replacement failed; restore failed (%s); saved image at %q (%s): %w",
			originalState(target, original, ops), aside, originalState(aside, original, ops), errors.Join(installErr, err))
	}
	// Keep the record if cleanup fails; next startup can finish without touching
	// the rollback backup. Cleanup failure must not turn restoration into data loss.
	_ = cleanupRecovery(target, ops)
	if state := originalState(target, original, ops); state != "original unchanged" {
		return fmt.Errorf("replacement failed; saved image restored (%s): %w", state, installErr)
	}
	return fmt.Errorf("replacement failed; original restored: %w", installErr)
}

// cleanupReplacement is deliberately conservative: an unrecognized directory,
// record, changed image or extra entry is left for operator inspection.
func cleanupReplacement(target string, ops replacementOps) error {
	if _, err := os.Lstat(target + replacementSuffix); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	unlock, err := acquireReplacementLock(target)
	if err != nil {
		if errors.Is(err, errReplacementBusy) {
			// The owner serializes replacement and cleanup. A later startup can
			// retry without warning about this expected concurrent operation.
			return nil
		}
		return err
	}
	defer unlock()
	err = cleanupRecovery(target, ops)
	if errors.Is(err, os.ErrNotExist) {
		// Simultaneous starts race to finish the same cleanup; an entry another
		// process just removed is not a failure. Look once more.
		err = cleanupRecovery(target, ops)
	}
	if err != nil {
		if _, statErr := os.Lstat(target + replacementSuffix); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
	}
	return err
}

// removeIfPresent treats an entry already removed by another start as done.
func removeIfPresent(ops replacementOps, path string) error {
	if err := ops.remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func cleanupRecovery(target string, ops replacementOps) error {
	ops = ops.defaults()
	dir := target + replacementSuffix
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unrecognized recovery directory %q", dir)
	}
	// Windows FileInfo loads its file ID lazily. Resolve it before cleanup so
	// a later comparison cannot accidentally identify a replacement directory.
	if !os.SameFile(info, info) {
		return errors.New("cannot establish recovery directory identity")
	}
	dirInfo := info
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != priorImageName && entry.Name() != replacementRecordName {
			return fmt.Errorf("unrecognized recovery entry %q", filepath.Join(dir, entry.Name()))
		}
	}
	if len(entries) == 0 {
		// Left by a start that stopped after removing the record. Nothing is owned.
		if err := removeIfPresent(ops, dir); err != nil {
			return fmt.Errorf("removing recovery directory: %w", err)
		}
		return nil
	}
	record := filepath.Join(dir, replacementRecordName)
	info, err = os.Lstat(record)
	const digestLength = sha256.Size * 2
	const recordLength = 2 * (digestLength + 1)
	if err != nil {
		return fmt.Errorf("checking recovery record: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != recordLength {
		return errors.New("unrecognized recovery record")
	}
	f, err := os.Open(record) // #nosec G304 -- fixed file inside the updater recovery directory
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, recordLength+1))
	_ = f.Close()
	if readErr != nil {
		return readErr
	}
	if len(data) != recordLength || data[digestLength] != '\n' || data[recordLength-1] != '\n' {
		return errors.New("invalid recovery record")
	}
	old, next := string(data[:digestLength]), string(data[digestLength+1:recordLength-1])
	if _, err := hex.DecodeString(old + next); err != nil {
		return fmt.Errorf("invalid recovery digests: %w", err)
	}
	current, err := ops.digest(target)
	if err != nil {
		return fmt.Errorf("checking installed image: %w", err)
	}
	aside := filepath.Join(dir, priorImageName)
	prior, err := ops.digest(aside)
	if errors.Is(err, os.ErrNotExist) {
		if current != next && current != old {
			return errors.New("installed image differs from recovery record")
		}
	} else {
		if err != nil {
			return fmt.Errorf("checking prior image: %w", err)
		}
		if prior != old || current != next {
			return errors.New("images differ from recovery record; retaining prior image")
		}
		if err := removeIfPresent(ops, aside); err != nil {
			return fmt.Errorf("removing prior image %q: %w", aside, err)
		}
	}
	if err := removeIfPresent(ops, record); err != nil {
		return fmt.Errorf("removing recovery record: %w", err)
	}
	if err := removeIfPresent(ops, dir); err != nil {
		// Retain the ownership record for retry if the final directory removal
		// fails. Never overwrite a colliding record or follow a replaced dir.
		currentDir, statErr := os.Lstat(dir)
		if statErr == nil && os.SameFile(dirInfo, currentDir) {
			if writeErr := ops.write(record, data, 0o600); writeErr != nil {
				err = errors.Join(err, writeErr)
			}
		}
		return fmt.Errorf("removing recovery directory: %w", err)
	}
	return nil
}
