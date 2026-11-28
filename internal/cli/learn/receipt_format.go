// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func withLegacyReceiptOutput(command, output, fallback string, write func() error) error {
	if output == "" {
		output = fallback
	}
	if !filepath.IsAbs(output) {
		return write()
	}
	const reader = "learn lifecycle receipts"
	if evidencename.ClaimsReceiptName(filepath.Base(filepath.Clean(output))) {
		return receiptinput.UnsupportedDirectory(command, reader)
	}
	// Promote and rollback require a provisioned parent.
	if command == "learn promote" || command == "learn rollback" {
		if _, err := existingLifecycleReceiptPath(output); err != nil {
			return err
		}
	}
	return withLegacyReceiptDirectory(command, filepath.Dir(output), func() error {
		if err := receiptinput.Refuse(output, command, reader); errors.Is(err, receiptinput.ErrUnsupported) {
			return receiptinput.UnsupportedDirectory(command, reader)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return write()
	})
}

func withLegacyReceiptDirectory(command, dir string, write func() error) error {
	const reader = "learn lifecycle receipts"
	check := func() error { return receiptinput.RefuseTree(dir, command, reader) }
	if err := check(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	err = recorder.WithEvidenceWriterCeremonyLock(resolved, func() error {
		if err := receiptinput.RefuseTree(resolved, command, reader); err != nil {
			return err
		}
		return write()
	})
	if errors.Is(err, recorder.ErrLegacyEvidenceFormat) {
		return receiptinput.UnsupportedDirectory(command, reader)
	}
	return err
}
