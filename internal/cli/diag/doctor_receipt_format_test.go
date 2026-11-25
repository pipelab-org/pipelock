// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestDoctorFlightRecorderRefusesV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		check := checkDoctorFlightRecorder(cfg)
		if check.Status != doctorStatusFail {
			t.Fatalf("unexpected doctor check: %+v", check)
		}
		testreceipt.RequiresV3Refusal(t, errors.New(check.Detail), "doctor", "flight recorder evidence health")
	})
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
	check := checkDoctorFlightRecorder(cfg)
	if check.Status != doctorStatusFail {
		t.Fatalf("unexpected doctor check on single-dash v3 file: %+v", check)
	}
	testreceipt.RequiresV3Refusal(t, errors.New(check.Detail), "doctor", "flight recorder evidence health")
}

// TestDoctorFlightRecorderRefusesConfiguredV3BeforeAndAfterFirstWrite holds the
// check to one answer for a host configured to write v3: doctor cannot
// understand v3 evidence, so it refuses whether the directory is missing, empty,
// holds only legacy shards, or already holds v3. Reporting ok before the first
// write and fail after it taught operators that the host went bad at the first
// receipt.
func TestDoctorFlightRecorderRefusesConfiguredV3BeforeAndAfterFirstWrite(t *testing.T) {
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
			check := checkDoctorFlightRecorder(cfg)
			if check.Status != doctorStatusFail {
				t.Fatalf("unexpected doctor check: %+v", check)
			}
			testreceipt.RequiresV3Refusal(t, errors.New(check.Detail), "doctor", "flight recorder evidence health")
		})
	}

	for _, format := range []string{"", config.ReceiptFormatLegacy} {
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = t.TempDir()
		cfg.FlightRecorder.ReceiptFormat = format
		if check := checkDoctorFlightRecorder(cfg); check.Status != doctorStatusOK {
			t.Fatalf("receipt_format %q on an empty directory: %+v", format, check)
		}
	}
}
