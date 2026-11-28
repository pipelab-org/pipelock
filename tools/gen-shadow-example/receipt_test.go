// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestExtractReceiptRefusesV3(t *testing.T) {
	dir := t.TempDir()
	testreceipt.V3(t, dir, false)
	if _, err := extractReceipt(dir); !errors.Is(err, recorder.ErrLegacyEvidenceFormat) {
		t.Fatalf("expected a receipt-profile refusal, got %v", err)
	}
}
