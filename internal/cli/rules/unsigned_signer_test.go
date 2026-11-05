// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
)

func TestRulesInspection_UnsignedSignerIdentityRejected(t *testing.T) {
	// Non-parallel: mutates the embedded keyring.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	setRulesKeyringHexForTest(t, hex.EncodeToString(pub))

	for _, command := range []string{"verify", "list", "status"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			setupUnsignedBundle(t, dir, testBundleName, []byte(validBundleYAML))
			lockPath := filepath.Join(dir, testBundleName, "bundle.lock")
			lock, err := domrules.ReadLockFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			lock.SignerFingerprint = domrules.KeyFingerprint(pub)
			if err := domrules.WriteLockFile(lockPath, lock); err != nil {
				t.Fatal(err)
			}
			cmd := testRootCmd()
			var out, stderr strings.Builder
			cmd.SetOut(&out)
			cmd.SetErr(&stderr)
			args := []string{"rules", command}
			if command == "status" {
				configPath := filepath.Join(t.TempDir(), "config.yaml")
				if err := os.WriteFile(configPath, []byte("rules:\n  rules_dir: "+dir+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--config", configPath, "--json")
			} else {
				args = append(args, "--rules-dir", dir)
				if command == "list" {
					args = append(args, "--json")
				}
			}
			cmd.SetArgs(args)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			err = cmd.Execute()
			switch command {
			case "verify":
				if err == nil || !strings.Contains(out.String(), "FAIL") || strings.Contains(out.String(), "SHA-256 OK") {
					t.Fatalf("want failed verification, got err=%v, output=%s", err, &out)
				}
			case "list":
				if err != nil {
					t.Fatal(err)
				}
				var entries []bundleListEntry
				if err := json.Unmarshal([]byte(out.String()), &entries); err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 || entries[0].Signed || !strings.HasPrefix(entries[0].CompatibilityStatus, "unverified:") {
					t.Fatalf("want unsigned, unverified entry, got %+v", entries)
				}
			case "status":
				if err == nil {
					t.Fatal("want degraded status error")
				}
				var report statusReport
				if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
					t.Fatal(err)
				}
				if report.Healthy || !report.Degraded || len(report.Errors) != 1 || len(report.Bundles) != 0 {
					t.Fatalf("want degraded status without loaded bundle, got %+v", report)
				}
			}
		})
	}
}
