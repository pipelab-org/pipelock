//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
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

func TestFleetReportVersionCompatibilityOutput(t *testing.T) {
	installFleetLicense(t)
	dir := t.TempDir()
	store, err := controlplane.OpenSQLiteAuditStore(t.Context(), filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	auditPub, auditPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestAuditBatch(t.Context(), cliTestAcceptedAuditBatch(t, auditPriv)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reportPub, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	const reportKeyID = "compatibility-report-key"
	keyPath := writeFleetReportKeyFile(t, dir, "report.key", reportKeyID, signing.PurposeFleetReportSigning, reportPriv)
	for _, tc := range []struct {
		name    string
		version string
		want    int
	}{
		{name: "implicit v2", want: 2},
		{name: "explicit v1", version: "1", want: 1},
		{name: "explicit v2", version: "2", want: 2},
	} {
		for _, toStdout := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stdout=%v", tc.name, toStdout), func(t *testing.T) {
				outPath := filepath.Join(t.TempDir(), "report.dsse.json")
				if toStdout {
					outPath = stdoutSentinel
				}
				args := []string{
					"--storage-dir", dir, "--org-id", "org-main", "--fleet-id", "prod",
					"--from", "2026-06-13T00:00:00Z", "--to", "2026-06-13T01:00:00Z",
					"--signing-key", keyPath, "--out", outPath,
					"--trusted-audit-key", "id=audit-key-1,inline=" + hex.EncodeToString(auditPub) + ",org=org-main,fleet=prod,instance=pl-1",
				}
				if tc.version != "" {
					args = append(args, "--report-version", tc.version)
				}
				cmd := fleetReportCmd()
				cmd.SetContext(t.Context())
				cmd.SetArgs(args)
				var stdout, stderr bytes.Buffer
				cmd.SetOut(&stdout)
				cmd.SetErr(&stderr)
				if err := cmd.Execute(); err != nil {
					t.Fatal(err)
				}
				notice := "notice: fleet receipt reports default to v2"
				if got := strings.Contains(stderr.String(), notice); got != (tc.version == "") {
					t.Fatalf("implicit-default notice=%v, version=%q stderr=%q", got, tc.version, stderr.String())
				}
				if tc.version == "" {
					for _, hint := range []string{"older v1-only verifiers reject v2", "--report-version 1", "upgrade older verifiers"} {
						if !strings.Contains(stderr.String(), hint) {
							t.Fatalf("compatibility notice missing %q: %q", hint, stderr.String())
						}
					}
				}
				summary := stdout.String()
				raw := stdout.Bytes()
				if toStdout {
					summary = stderr.String()
				} else {
					var err error
					raw, err = os.ReadFile(filepath.Clean(outPath))
					if err != nil {
						t.Fatal(err)
					}
				}
				if !strings.Contains(summary, fmt.Sprintf("report_version: %d\n", tc.want)) {
					t.Fatalf("summary missing actual version: %q", summary)
				}
				if strings.Contains(stdout.String(), notice) {
					t.Fatalf("stdout contains compatibility notice: %q", stdout.String())
				}
				var envelope fleetreceipt.Envelope
				if err := json.Unmarshal(raw, &envelope); err != nil {
					t.Fatalf("output is not a clean DSSE envelope: %v", err)
				}
				verified, err := fleetreceipt.VerifyEnvelope(envelope, map[string]ed25519.PublicKey{reportKeyID: reportPub})
				if err != nil {
					t.Fatal(err)
				}
				if got := verified.Statement.Predicate.SchemaVersion; got != tc.want {
					t.Fatalf("emitted version=%d want %d", got, tc.want)
				}
			})
		}
	}
}
