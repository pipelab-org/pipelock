// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestExplainResponseHostCapReadLimit(t *testing.T) {
	now := time.Now().UTC()
	c := config.Defaults()
	c.ResponseScanning.SizeExemptDomains = []string{"downloads.vendor.example"}
	c.ResponseScanning.SizeExemptScanLimits = []config.ResponseSizeScanLimit{{
		Host: "downloads.vendor.example", MaxBytes: 128 << 20, Owner: "operator", Reason: "scanned fixture",
		Added: now.Add(-2 * time.Hour).Format(time.RFC3339Nano), Expires: now.Add(time.Hour).Format(time.RFC3339Nano),
	}}
	if got := explainResponseReadLimit(c); got != 128<<20 {
		t.Fatalf("live host cap not readable: %d", got)
	}
	c.ResponseScanning.SizeExemptScanLimits[0].Expires = now.Add(-time.Hour).Format(time.RFC3339Nano)
	if got := explainResponseReadLimit(c); got != config.DefaultSizeExemptScanMaxBytes {
		t.Fatalf("expired host cap still used: %d", got)
	}
	// The diagnostic's own fixed allocation safety bound still applies.
	c.ResponseScanning.SizeExemptScanLimits[0].Expires = now.Add(time.Hour).Format(time.RFC3339Nano)
	c.ResponseScanning.SizeExemptScanLimits[0].MaxBytes = 512 << 20
	c.ResponseScanning.SizeExemptScanMaxInflightBytes = 512 << 20
	if got := explainResponseReadLimit(c); got != explainResponseMaxReadBytes {
		t.Fatalf("diagnostic allocation bound lost: %d", got)
	}
}
