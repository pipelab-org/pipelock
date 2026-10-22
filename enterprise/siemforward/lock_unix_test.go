//go:build enterprise && !windows

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package siemforward

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStateLockErrorUnix(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		err        error
	}{
		{"contention", "locked by another Pipelock process", unix.EWOULDBLOCK},
		{"other_failure", "lock siem forwarder spool", unix.ENOLCK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := stateLockError("spool", tc.err)
			if !errors.Is(got, tc.err) || !strings.Contains(got.Error(), tc.want) {
				t.Fatalf("stateLockError = %v, want %s wrapping %v", got, tc.want, tc.err)
			}
			if tc.name == "other_failure" && strings.Contains(got.Error(), "another Pipelock process") {
				t.Fatalf("non-contention error blamed another process: %v", got)
			}
		})
	}
}
