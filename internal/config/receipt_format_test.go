// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestFlightRecorderReceiptFormatLoad(t *testing.T) {
	const base = "flight_recorder:\n  enabled: true\n  dir: evidence\n  signing_key_path: signer.key\n"
	for _, tc := range []struct {
		name  string
		extra string
		want  string
		fail  bool
	}{
		{name: "omitted"},
		{name: "null", extra: "  receipt_format: null\n"},
		{name: "legacy", extra: "  receipt_format: legacy\n", want: ReceiptFormatLegacy},
		{name: "v3", extra: "  receipt_format: v3\n", want: ReceiptFormatV3},
		{name: "unknown", extra: "  receipt_format: future\n", fail: true},
		{name: "multiple chains", extra: "  receipt_format: v3\n  receipt_chains: 2\n", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(base + tc.extra))
			if tc.fail {
				if err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_format") {
					t.Fatalf("expected named format error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.FlightRecorder.ReceiptFormat != tc.want {
				t.Fatalf("format = %q, want %q", cfg.FlightRecorder.ReceiptFormat, tc.want)
			}
		})
	}
}
