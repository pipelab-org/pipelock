// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func withLegacyReceiptOutput(command, output, fallback string, write func() error) error {
	if output == "" {
		output = fallback
	}
	if !filepath.IsAbs(output) {
		return write()
	}
	return withLegacyReceiptDirectory(command, filepath.Dir(output), write)
}

func withLegacyReceiptDirectory(command, dir string, write func() error) error {
	const reader = "learn lifecycle receipts"
	check := func() error { return receiptinput.Refuse(dir, command, reader) }
	if err := check(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return write()
		}
		return err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	err = recorder.WithEvidenceWriterCeremonyLock(resolved, func() error {
		if err := receiptinput.Refuse(resolved, command, reader); err != nil {
			return err
		}
		return write()
	})
	if errors.Is(err, recorder.ErrLegacyEvidenceFormat) {
		return receiptinput.UnsupportedDirectory(command, reader)
	}
	return err
}
