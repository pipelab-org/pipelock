// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func requireDoctorV3Warning(t *testing.T, check doctorReportCheck, dir string) {
	t.Helper()
	want := "receipt v3 evidence is not verified by doctor; run 'pipelock verify-receipt --chain " + dir + "'"
	if check.Status != doctorStatusWarn || check.Enforcing || check.Detail != want {
		t.Fatalf("doctor check = %+v, want warning %q", check, want)
	}
}

func TestDoctorFlightRecorderDelegatesV3Verification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		damaged bool
	}{
		{"signed", false},
		{"damaged", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, pub := testreceipt.V3(t, dir, tc.damaged)
			cfg := config.Defaults()
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = dir
			cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
			cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}
			requireDoctorV3Warning(t, checkDoctorFlightRecorder(cfg), dir)
		})
	}
}

func TestDoctorFlightRecorderRefusesSingleDashV3EvidenceFile(t *testing.T) {
	v3File, _ := testreceipt.V3(t, t.TempDir(), false)
	v3Data, err := os.ReadFile(filepath.Clean(v3File))
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{".", "child"} {
		t.Run(location, func(t *testing.T) {
			dir := t.TempDir()
			shardDir := filepath.Join(dir, location)
			if err := os.MkdirAll(shardDir, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(shardDir, "evidence-v3.jsonl"), v3Data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = dir
			cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
			requireDoctorV3Warning(t, checkDoctorFlightRecorder(cfg), dir)
		})
	}
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
			cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
			requireDoctorV3Warning(t, checkDoctorFlightRecorder(cfg), cfg.FlightRecorder.Dir)
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

	check := checkDoctorFlightRecorder(cfg)
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

		check := checkDoctorFlightRecorder(cfg)
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

		check := checkDoctorFlightRecorder(cfg)
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

		check := checkDoctorFlightRecorder(cfg)
		if check.Status != doctorStatusFail || check.Enforcing {
			t.Fatalf("read-only v3 dir = %+v, want fail and Enforcing=false", check)
		}
	})

	t.Run("nested v3 evidence prevents OK", func(t *testing.T) {
		dir := t.TempDir()
		child := filepath.Join(dir, "child")
		if err := os.Mkdir(child, 0o750); err != nil {
			t.Fatal(err)
		}
		testreceipt.V3(t, child, true)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
		requireDoctorV3Warning(t, checkDoctorFlightRecorder(cfg), dir)
	})

	t.Run("bad signing_key_path fails instead of warning", func(t *testing.T) {
		dir := t.TempDir()
		testreceipt.V3(t, dir, false)
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.ReceiptFormat = config.ReceiptFormatV3
		cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "missing.key")

		check := checkDoctorFlightRecorder(cfg)
		if check.Status != doctorStatusFail || check.Enforcing {
			t.Fatalf("missing signing_key_path file = %+v, want fail and Enforcing=false", check)
		}
	})

	t.Run("symlink evidence file is left to the verifier", func(t *testing.T) {
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

		requireDoctorV3Warning(t, checkDoctorFlightRecorder(cfg), dir)
	})
}

func TestDoctorFlightRecorderExplicitV3RequiresRuntimeConfig(t *testing.T) {
	for _, missing := range []string{"enabled", "dir", "signing_key_path"} {
		t.Run(missing, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = t.TempDir()
			cfg.FlightRecorder.SigningKeyPath = saveDoctorTestKey(t)
			cfg.FlightRecorder.ReceiptFormat = config.ReceiptFormatV3
			switch missing {
			case "enabled":
				cfg.FlightRecorder.Enabled = false
			case "dir":
				cfg.FlightRecorder.Dir = ""
			case "signing_key_path":
				cfg.FlightRecorder.SigningKeyPath = ""
			}
			check := checkDoctorFlightRecorder(cfg)
			if check.Status != doctorStatusFail || check.Enforcing || !strings.Contains(check.Detail, "signing_key_path") {
				t.Fatalf("explicit v3 without %s = %+v, want configuration failure", missing, check)
			}
		})
	}
}

func TestCheckDoctorFlightRecorderRejectsInvalidEvidenceLocation(t *testing.T) {
	t.Run("file instead of directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = path
		check := checkDoctorFlightRecorder(cfg)
		if check.Status != doctorStatusFail || !strings.Contains(check.Detail, "not a directory") {
			t.Fatalf("check: %+v", check)
		}
	})
	t.Run("legacy configured with v3 evidence", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "stream.receipt-v3.jsonl"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.ReceiptFormat = config.ReceiptFormatLegacy
		check := checkDoctorFlightRecorder(cfg)
		if check.Status != doctorStatusFail || !strings.Contains(check.Detail, "requires a new evidence directory") {
			t.Fatalf("check: %+v", check)
		}
	})
}

func TestLogsRejectsReceiptAndOversizedInput(t *testing.T) {
	for _, tc := range []struct{ name, filename, content, want string }{
		{"profile name", "stream.receipt-v3.jsonl", "{}\n", "receipt v3 evidence"},
		{"profile content", "audit.log", "  {\"payloadType\":\"application/vnd.pipelock.receipt.v3+json\"}\n", "receipt v3 evidence"},
		{"oversized legacy line", "audit.log", strings.Repeat("x", 70<<10), "oversized line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.filename)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := logsRoot()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"logs", "--file", path})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLogsFollowRejectsReceiptAndOversizedInput(t *testing.T) {
	for _, tc := range []struct{ name, initial, content, want string }{
		{"receipt", "", "{\"payloadType\":\"application/vnd.pipelock.receipt.v3+json\"}", "receipt v3 evidence"},
		{"split receipt", "{\"pay", "loadType\":\"application/vnd.pipelock.receipt.v3+json\"}\n", "receipt v3 evidence"},
		{"oversized", "", strings.Repeat("x", 70<<10), "oversized line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			if err := os.WriteFile(path, []byte("ready\n"+tc.initial), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := logsRoot()
			cmd.SetContext(ctx)
			output := &lockedStringWriter{}
			cmd.SetOut(output)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"logs", "--file", path, "--follow"})
			done := make(chan error, 1)
			go func() { done <- cmd.Execute() }()
			waitForLogOutput(t, output, done, cancel, "ready")
			file, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := file.WriteString(tc.content)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("append: %v, close: %v", writeErr, closeErr)
			}
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %q", err, tc.want)
				}
				if tc.initial != "" && strings.Contains(output.String(), tc.initial) {
					t.Fatal("printed an unclassified partial line")
				}
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Fatal("follow did not reject input")
			}
		})
	}
}
