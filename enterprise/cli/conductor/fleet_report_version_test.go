//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestFleetReportVersionFlagAndLicenseGate(t *testing.T) {
	cmd := fleetReportCmd()
	version, err := cmd.Flags().GetInt("report-version")
	if err != nil || version != 2 {
		t.Fatalf("default version=%d err=%v", version, err)
	}
	for _, token := range []string{"", "invalid"} {
		t.Run("license="+token, func(t *testing.T) {
			t.Setenv(license.EnvLicenseKey, token)
			t.Setenv(license.EnvLicensePublicKey, "")
			t.Setenv(license.EnvLicenseCRLFile, "")
			cmd := fleetReportCmd()
			cmd.SetArgs([]string{"--report-version", "1"})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			if err := cmd.Execute(); err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
				t.Fatalf("license gate=%v", err)
			}
		})
	}
	installFleetLicense(t)
	for _, version := range []string{"0", "99"} {
		cmd = fleetReportCmd()
		cmd.SetArgs([]string{"--report-version", version})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--report-version") {
			t.Fatalf("unsupported report version=%v", err)
		}
	}
}
