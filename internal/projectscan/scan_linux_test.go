// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package projectscan

import "testing"

// /proc/self/mem is a regular file whose reads at offset 0 fail, which
// exercises the read-error path after the regular-file check passes.
func TestReadSecretCandidate_ReadErrorReportsUnreadable(t *testing.T) {
	data, reason := readSecretCandidate("/proc/self/mem")
	if reason != "unreadable" || data != nil {
		t.Fatalf("read error = %d bytes, %q; want unreadable", len(data), reason)
	}
}
