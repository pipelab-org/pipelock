// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

// Package receiptinput protects legacy evidence readers from unsupported receipt formats.
package receiptinput

import (
	"errors"
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

// ErrUnsupported marks a refusal from a reader without v3 support.
var ErrUnsupported = errors.New("receipt v3 evidence is not supported")

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
	if v3.ClaimsContent(payload) {
		return unsupported(command, reader, false)
	}
	return nil
}
