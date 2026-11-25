// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"io"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestAnchorReceiptsRefusesV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, path string) {
		testreceipt.RequiresV3Refusal(t, runReceipts(io.Discard, dir, receiptsOptions{asDir: true}), "anchor receipts", "the receipt anchor")
		testreceipt.RequiresV3Refusal(t, runReceipts(io.Discard, path, receiptsOptions{}), "anchor receipts", "the receipt anchor")
	})
}
