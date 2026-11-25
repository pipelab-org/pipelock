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
