// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestIngestRefusesReceiptV3(t *testing.T) {
	path, _ := testreceipt.V3(t, t.TempDir(), false)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	entries, errs := Stream(bytes.NewReader(data), StreamOptions{})
	for entry := range entries {
		t.Errorf("unexpected entry: %+v", entry)
	}
	testreceipt.RequiresV3Refusal(t, <-errs, "learn compile", "contract inference")
}
