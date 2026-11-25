// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestVerifyPacketRefusesReceiptV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		testreceipt.RequiresV3Refusal(t, VerifyPacketDir(dir, ""), "audit packet", "the audit packet verifier")
	})
	path, _ := testreceipt.V3(t, t.TempDir(), false)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	testreceipt.RequiresV3Refusal(t, VerifyPacketBytes(nil, data, ""), "audit packet", "the audit packet verifier")
}
