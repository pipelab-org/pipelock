// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/sha256"
	"hash"
	"io"
)

// EvidenceFileDigest identifies the exact bytes of one evidence file.
type EvidenceFileDigest struct {
	Size   int64
	SHA256 [sha256.Size]byte
}

// ValidateEvidenceFileDigest validates path exactly as ValidateEvidenceFile
// does and also returns the SHA-256 of the bytes it validated. The digest is
// taken in the same read as the validation, so a file that changes between
// validation and hashing cannot be recorded as validated: the change check
// that guards the read covers both. The digest is meaningful only when the
// error is nil.
func ValidateEvidenceFileDigest(path string, validate func(Entry) error) (EvidenceFileDigest, error) {
	return validateEvidenceFile(path, validate, sha256.New())
}

// DigestEvidenceFile hashes an evidence file without parsing it. It applies
// the same regular-file, no-symlink and unchanged-while-read checks as the
// validators, so a digest describes one stable file.
func DigestEvidenceFile(path string) (EvidenceFileDigest, error) {
	file, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		return EvidenceFileDigest{}, err
	}
	defer func() { _ = file.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(file, 0, info.Size()))
	if err != nil {
		return EvidenceFileDigest{}, err
	}
	if changed := ensureEvidenceFileUnchanged(file, info); changed != nil {
		return EvidenceFileDigest{}, changed
	}
	if n != info.Size() {
		return EvidenceFileDigest{}, ErrEvidenceFileChanged
	}
	return digestOf(h, n), nil
}

func validateEvidenceFile(path string, validate func(Entry) error, h hash.Hash) (EvidenceFileDigest, error) {
	file, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		return EvidenceFileDigest{}, err
	}
	defer func() { _ = file.Close() }()
	validator := evidenceTailValidator(validate)
	if err := inspectJSONLTail(file, info, path, validator); err != nil {
		return EvidenceFileDigest{}, err
	}
	var input io.Reader = io.NewSectionReader(file, 0, info.Size())
	counted := &countingWriter{}
	if h != nil {
		counted.w = h
		input = io.TeeReader(input, counted)
	}
	err = inspectJSONLRecords(input, path, validator, false)
	if changed := ensureEvidenceFileUnchanged(file, info); changed != nil {
		return EvidenceFileDigest{}, changed
	}
	if err != nil || h == nil {
		return EvidenceFileDigest{}, err
	}
	// The record reader stops at EOF on success, so every byte has passed
	// through the hash. Anything else means the digest does not describe the
	// validated file, and it must not be reported as one.
	if counted.n != info.Size() {
		return EvidenceFileDigest{}, ErrEvidenceFileChanged
	}
	return digestOf(h, counted.n), nil
}

func digestOf(h hash.Hash, size int64) EvidenceFileDigest {
	d := EvidenceFileDigest{Size: size}
	copy(d.SHA256[:], h.Sum(nil))
	return d
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
