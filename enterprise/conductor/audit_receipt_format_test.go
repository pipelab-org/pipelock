//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestAuditNamespaceRefusesReceiptV3(t *testing.T) {
	dir := t.TempDir()
	path, _ := testreceipt.V3(t, dir, false)
	payload, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := legacySessionFixture(t)
	env.PayloadBytes = uint64(len(payload))
	env.PayloadSHA256 = testBytesHash(payload)
	for name, candidate := range map[string][]byte{
		"direct":          payload,
		"leading-newline": append([]byte("\n"), payload...),
		"after-legacy":    append([]byte(`{"v":1,"seq":1,"type":"action_receipt"}`+"\n"), payload...),
	} {
		t.Run(name, func(t *testing.T) {
			envCopy := env
			envCopy.PayloadBytes = uint64(len(candidate))
			envCopy.PayloadSHA256 = testBytesHash(candidate)
			_, err := envCopy.PayloadNamespace(t.Context(), candidate)
			testreceipt.RequiresV3Refusal(t, err, "audit batch", "the fleet audit receiver")
		})
	}
}
