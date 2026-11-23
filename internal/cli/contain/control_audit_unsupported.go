// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import (
	"errors"
	"io"
)

func runControlAudit(_ io.Writer, _ controlAuditOptions) error {
	return errors.New("audit-workspace requires Linux; run sudo pipelock contain audit-workspace --help on the Linux host")
}
