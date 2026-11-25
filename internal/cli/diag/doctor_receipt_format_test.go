// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"

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
				cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
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

func saveDoctorTestKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signer.key")
	if err := signing.SavePrivateKey(priv, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDoctorFlightRecorderLegacyConfigRefusesV3Directory(t *testing.T) {
	dir := t.TempDir()
	_, pub := testreceipt.V3(t, dir, false)
	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = dir
	cfg.FlightRecorder.ReceiptFormat = config.ReceiptFormatLegacy
	cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
	cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}

	check := checkDoctorFlightRecorder(t.Context(), cfg)
	if check.Status != doctorStatusFail || check.Enforcing {
		t.Fatalf("explicit legacy config on v3 directory = %+v, want fail and Enforcing=false", check)
	}
	if !strings.Contains(check.Detail, "legacy") || !strings.Contains(check.Next, "pipelock verify-receipt --chain") {
		t.Fatalf("unexpected diagnostic for legacy config on v3 directory: %+v", check)
	}
}

func TestDoctorFlightRecorderV3RuntimePreconditions(t *testing.T) {
	t.Run("missing signing_key_path cannot report OK", func(t *testing.T) {
		dir := t.TempDir()
		_, pub := testreceipt.V3(t, dir, false)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusFail || check.Enforcing {
			t.Fatalf("missing signing_key_path = %+v, want fail and Enforcing=false", check)
		}
	})

	t.Run("incompatible anchor config fails", func(t *testing.T) {
		dir := t.TempDir()
		_, pub := testreceipt.V3(t, dir, false)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}
		cfg.FlightRecorder.Anchor.LocalLog = filepath.Join(t.TempDir(), "anchor.jsonl")

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusFail || check.Enforcing {
			t.Fatalf("incompatible anchor config = %+v, want fail and Enforcing=false", check)
		}
	})

	t.Run("read-only v3 directory fails", func(t *testing.T) {
		dir := t.TempDir()
		_, pub := testreceipt.V3(t, dir, false)
		if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- read-only directory fixture for permission test.
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.Chmod(dir, 0o700) // #nosec G302 -- restore test dir permissions for cleanup.
		})
		if pathWritableDir(dir) {
			t.Skip("process can still write to chmod 0500 directory")
		}
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.ReceiptFormat = config.ReceiptFormatV3
		cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusFail || check.Enforcing {
			t.Fatalf("read-only v3 dir = %+v, want fail and Enforcing=false", check)
		}
	})

	t.Run("nested v3 evidence prevents OK", func(t *testing.T) {
		dir := t.TempDir()
		_, pub := testreceipt.V3(t, dir, false)
		child := filepath.Join(dir, "child")
		if err := os.Mkdir(child, 0o750); err != nil {
			t.Fatal(err)
		}
		testreceipt.V3(t, child, true)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusFail || check.Enforcing {
			t.Fatalf("top-level valid v3 with nested damaged v3 = %+v, want fail and Enforcing=false", check)
		}
	})

	t.Run("bad signing_key_path fails instead of warning", func(t *testing.T) {
		dir := t.TempDir()
		testreceipt.V3(t, dir, false)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.ReceiptFormat = config.ReceiptFormatV3
		cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "missing.key")

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusFail || check.Enforcing {
			t.Fatalf("missing signing_key_path file = %+v, want fail and Enforcing=false", check)
		}
	})

	t.Run("symlink evidence file fails instead of warning", func(t *testing.T) {
		dir := t.TempDir()
		_, pub := testreceipt.V3(t, dir, false)
		outside := filepath.Join(t.TempDir(), "outside.jsonl")
		if err := os.WriteFile(outside, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "evidence-proxy-0.jsonl")); err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusFail || check.Enforcing {
			t.Fatalf("symlink evidence file = %+v, want fail and Enforcing=false", check)
		}
	})
}

func TestDoctorFlightRecorderV3RespectsInlineBudget(t *testing.T) {
	t.Run("byte cap warns instead of verifying unbounded data", func(t *testing.T) {
		orig := doctorV3MaxBytes
		doctorV3MaxBytes = 16
		t.Cleanup(func() { doctorV3MaxBytes = orig })

		dir := t.TempDir()
		_, pub := testreceipt.V3(t, dir, false)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusWarn || check.Enforcing {
			t.Fatalf("over byte cap = %+v, want warn and Enforcing=false", check)
		}
		if !strings.Contains(check.Next, "pipelock verify-receipt --chain") {
			t.Fatalf("missing offline verifier guidance: %+v", check)
		}
	})

	t.Run("file cap warns instead of verifying unbounded files", func(t *testing.T) {
		orig := doctorV3MaxFiles
		doctorV3MaxFiles = 0
		t.Cleanup(func() { doctorV3MaxFiles = orig })

		dir := t.TempDir()
		_, pub := testreceipt.V3(t, dir, false)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusWarn || check.Enforcing {
			t.Fatalf("over file cap = %+v, want warn and Enforcing=false", check)
		}
		if !strings.Contains(check.Next, "pipelock verify-receipt --chain") {
			t.Fatalf("missing offline verifier guidance: %+v", check)
		}
	})

	t.Run("entry cap warns instead of reading unbounded directory", func(t *testing.T) {
		orig := doctorV3MaxEntries
		doctorV3MaxEntries = 0
		t.Cleanup(func() { doctorV3MaxEntries = orig })

		dir := t.TempDir()
		_, pub := testreceipt.V3(t, dir, false)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}

		check := checkDoctorFlightRecorder(t.Context(), cfg)
		if check.Status != doctorStatusWarn || check.Enforcing {
			t.Fatalf("over entry cap = %+v, want warn and Enforcing=false", check)
		}
		if !strings.Contains(check.Next, "pipelock verify-receipt --chain") {
			t.Fatalf("missing offline verifier guidance: %+v", check)
		}
	})
}
