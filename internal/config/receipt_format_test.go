// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

const receiptFormatTestBase = "flight_recorder:\n  enabled: true\n  dir: evidence\n  signing_key_path: signer.key\n"

func TestFlightRecorderReceiptFormatLoad(t *testing.T) {
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
			cfg, err := LoadBytes([]byte(receiptFormatTestBase + tc.extra))
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

func TestFlightRecorderReceiptV3RequiresSigningAndStorage(t *testing.T) {
	for _, tc := range []struct {
		name, present, missing string
	}{
		{name: "disabled", present: "enabled: true", missing: "enabled: false"},
		{name: "no directory", present: "dir: evidence", missing: "dir: ''"},
		{name: "no signing key", present: "signing_key_path: signer.key", missing: "signing_key_path: ''"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(receiptFormatTestBase, tc.present, tc.missing, 1) + "  receipt_format: v3\n"
			_, err := LoadBytes([]byte(input))
			if err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_format v3 requires flight_recorder.enabled, dir, and signing_key_path") {
				t.Fatalf("expected the v3 prerequisites error, got %v", err)
			}
		})
	}
}
