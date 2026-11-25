// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"errors"
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
