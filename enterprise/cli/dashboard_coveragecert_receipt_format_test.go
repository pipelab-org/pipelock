//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestCoverageCertRefusesReceiptV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		err := runCoverageCertGenerate(&cobra.Command{}, coverageCertGenerateOptions{
			agent: "example", receiptDir: dir,
			windowStart: "2026-01-01T00:00:00Z", windowEnd: "2026-01-01T01:00:00Z",
		})
		testreceipt.RequiresV3Refusal(t, err, "dashboard coverage-cert generate", "coverage certificates")
	})
}

func TestCoverageCertRefusesReceiptV3InResolvedSubdir(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "location-a")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, sub, false)
	if err := os.WriteFile(filepath.Join(sub, "evidence-proxy-0.jsonl"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	err := runCoverageCertGenerate(&cobra.Command{}, coverageCertGenerateOptions{
		agent: "example", receiptDir: root,
		windowStart: "2026-01-01T00:00:00Z", windowEnd: "2026-01-01T01:00:00Z",
	})
	testreceipt.RequiresV3Refusal(t, err, "dashboard coverage-cert generate", "coverage certificates")
}
