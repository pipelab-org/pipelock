// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

// ErrLegacyEvidenceFormat indicates the directory has switched to v3.
var ErrLegacyEvidenceFormat = errors.New("legacy receipts require a new evidence directory after a v3 switch")

var tryAcquireEvidenceCeremonyLock = tryLockEvidenceFileForExpiry

// EvidenceCeremonyLock proves that no recorder is writing in an evidence
// directory and prevents a recorder from starting until the lock is released.
type EvidenceCeremonyLock struct {
	file *os.File
}

// AcquireEvidenceCeremonyLock takes exclusive, non-blocking ownership of an
// evidence directory for an offline receipt ceremony.
func AcquireEvidenceCeremonyLock(dir string) (*EvidenceCeremonyLock, error) {
	if !supportsEvidenceCeremonyLock() {
		return nil, errors.New("receipt ceremony locking is unsupported on this platform")
	}
	file, _, err := openEvidenceCeremonyLock(dir)
	if err != nil {
		return nil, err
	}
	locked, err := tryAcquireEvidenceCeremonyLock(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("locking receipt ceremony: %w", err)
	}
	if !locked {
		_ = file.Close()
		return nil, errors.New("receipt ceremony requires a stopped recorder; evidence directory is still in use")
	}
	return &EvidenceCeremonyLock{file: file}, nil
}

// Close releases exclusive ceremony ownership.
func (l *EvidenceCeremonyLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockEvidenceFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}

func acquireEvidenceWriterCeremonyLock(dir string) (*os.File, os.FileInfo, error) {
	if !supportsEvidenceCeremonyLock() {
		return nil, nil, checkLegacyEvidenceFormat(dir)
	}
	file, info, err := openEvidenceCeremonyLock(dir)
	if err != nil {
		return nil, nil, err
	}
	if err := tryLockEvidenceFileForCeremonyWrite(file); err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("locking recorder against receipt ceremonies: %w", err)
	}
	if err := checkLegacyEvidenceFormat(dir); err != nil {
		return nil, nil, errors.Join(err, unlockEvidenceFile(file), file.Close())
	}
	return file, info, nil
}

// checkLegacyEvidenceFormat refuses a legacy write into a directory that the
// receipt-profile verifier claims. It applies the claim rule of v3.ClaimsInput,
// which this package cannot import: any "*.receipt-vN.jsonl" name, and receipt
// content under a legacy candidate name. The rules live in evidencename so the
// two cannot drift; a parity test in receiptinput fails if the loops disagree.
//
// A directory that does not exist yet holds no v3 files; the caller's own open
// or create reports whether it can be used. A candidate file that cannot be read
// leaves the directory unclassified, which refuses the write rather than risk
// splitting one directory across formats.
func checkLegacyEvidenceFormat(dir string) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking legacy evidence directory format: %w", err)
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return fmt.Errorf("checking legacy evidence directory format: %w", err)
	}
	var probeErr error
	for _, entry := range entries {
		name := entry.Name()
		if _, claimed := evidencename.ReceiptProfileVersion(name); claimed {
			return ErrLegacyEvidenceFormat
		}
		if entry.IsDir() || !entry.Type().IsRegular() || !evidencename.IsLegacyReceiptCandidate(name) {
			continue
		}
		claimed, err := fileClaimsReceiptProfile(filepath.Join(resolved, name))
		if claimed {
			return ErrLegacyEvidenceFormat
		}
		if probeErr == nil {
			probeErr = err
		}
	}
	if probeErr != nil {
		return fmt.Errorf("checking legacy evidence directory format: %w", probeErr)
	}
	return nil
}

func fileClaimsReceiptProfile(path string) (bool, error) {
	file, _, err := OpenEvidenceFile(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	prefix := make([]byte, len(evidencename.ReceiptProfilePrefix))
	if _, err := io.ReadFull(file, prefix); errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("read evidence prefix: %w", err)
	}
	return evidencename.ClaimsReceiptContent(prefix), nil
}

// WithEvidenceWriterCeremonyLock runs one non-recorder evidence write under
// the same shared directory lock used by Recorder. An offline ceremony holding
// the exclusive lock makes this fail before fn can mutate the directory.
func WithEvidenceWriterCeremonyLock(dir string, fn func() error) (err error) {
	if fn == nil {
		return errors.New("evidence writer callback is required")
	}
	file, _, err := acquireEvidenceWriterCeremonyLock(dir)
	if err != nil {
		return err
	}
	if file == nil {
		return fn()
	}
	defer func() {
		recovered := recover()
		err = errors.Join(err, unlockEvidenceFile(file), file.Close())
		if recovered != nil {
			panic(recovered)
		}
	}()
	return fn()
}

func (r *Recorder) ensureEvidenceWriterCeremonyLock(dirInfo os.FileInfo) error {
	if !supportsEvidenceCeremonyLock() {
		return nil
	}
	if r.ceremonyLock != nil && r.ceremonyDir != nil &&
		dirInfo != nil && os.SameFile(dirInfo, r.ceremonyDir) {
		return nil
	}
	if err := r.releaseEvidenceWriterCeremonyLock(); err != nil {
		return fmt.Errorf("release stale receipt ceremony lock: %w", err)
	}
	lock, lockDirInfo, err := acquireEvidenceWriterCeremonyLock(r.cfg.Dir)
	if err != nil {
		return err
	}
	r.ceremonyLock = lock
	r.ceremonyDir = lockDirInfo
	return nil
}

func (r *Recorder) releaseEvidenceWriterCeremonyLock() error {
	if r.ceremonyLock == nil {
		return nil
	}
	unlockErr := unlockEvidenceFile(r.ceremonyLock)
	closeErr := r.ceremonyLock.Close()
	r.ceremonyLock = nil
	r.ceremonyDir = nil
	return errors.Join(unlockErr, closeErr)
}

func openEvidenceCeremonyLock(dir string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(filepath.Clean(dir), os.O_RDONLY|evidenceReadNoFollowFlag, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("opening evidence directory for receipt ceremony lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat evidence directory for receipt ceremony lock: %w", err)
	}
	if !info.IsDir() {
		_ = file.Close()
		return nil, nil, errors.New("receipt ceremony lock target is not an evidence directory")
	}
	return file, info, nil
}
