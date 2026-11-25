// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestDoctorFlightRecorderVerifiesV3(t *testing.T) {
	for _, tc := range []struct {
		name, status, verdict string
		damaged, pinned       bool
	}{
		{"pinned", doctorStatusOK, "VALID", false, true},
		{"damaged", doctorStatusFail, "INVALID", true, true},
		{"unpinned", doctorStatusWarn, "SELF-CONSISTENT ONLY", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, pub := testreceipt.V3(t, dir, tc.damaged)
			cfg := config.Defaults()
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = dir
			if tc.pinned {
				cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}
			}
			check := checkDoctorFlightRecorder(t.Context(), cfg)
			if check.Status != tc.status || !strings.Contains(check.Detail, tc.verdict) {
				t.Fatalf("doctor check = %+v, want %s with %q", check, tc.status, tc.verdict)
			}
		})
	}
}

func TestDoctorFlightRecorderRefusesSingleDashV3EvidenceFile(t *testing.T) {
	v3File, _ := testreceipt.V3(t, t.TempDir(), false)
	v3Data, err := os.ReadFile(filepath.Clean(v3File))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence-v3.jsonl"), v3Data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = dir
	check := checkDoctorFlightRecorder(t.Context(), cfg)
	if check.Status != doctorStatusWarn {
		t.Fatalf("unexpected doctor check on single-dash v3 file: %+v", check)
	}
	testreceipt.RequiresV3Refusal(t, errors.New(check.Detail), "doctor", "flight recorder evidence health")
}

func TestDoctorFlightRecorderConfiguredV3WithoutVerifiedEvidenceWarns(t *testing.T) {
	legacyShard := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"empty directory", func(t *testing.T) string { return t.TempDir() }},
		{"directory not created yet", func(t *testing.T) string { return filepath.Join(t.TempDir(), "runtime-created") }},
		{"legacy shards only", func(t *testing.T) string {
			dir := t.TempDir()
			legacyShard(t, dir)
			return dir
		}},
		{"after the first v3 write", func(t *testing.T) string {
			dir := t.TempDir()
			testreceipt.V3(t, dir, false)
			return dir
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = tc.setup(t)
			cfg.FlightRecorder.ReceiptFormat = config.ReceiptFormatV3
			check := checkDoctorFlightRecorder(t.Context(), cfg)
			if check.Status != doctorStatusWarn || !strings.Contains(check.Next, "pipelock verify-receipt") {
				t.Fatalf("unexpected doctor check: %+v", check)
			}
		})
	}

	for _, format := range []string{"", config.ReceiptFormatLegacy} {
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = t.TempDir()
		cfg.FlightRecorder.ReceiptFormat = format
		if check := checkDoctorFlightRecorder(t.Context(), cfg); check.Status != doctorStatusOK {
			t.Fatalf("receipt_format %q on an empty directory: %+v", format, check)
		}
	}
}
