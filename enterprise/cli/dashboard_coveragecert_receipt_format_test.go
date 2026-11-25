//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
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
