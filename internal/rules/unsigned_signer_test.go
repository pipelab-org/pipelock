// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestVerifyIntegrity_UnsignedSignerIdentityRejected(t *testing.T) {
	t.Parallel()

	data := []byte("name: unsigned-bundle\n")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, bundleFilename), data, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	for _, fingerprint := range []string{"claimed-signer", " "} {
		t.Run(fingerprint, func(t *testing.T) {
			for name, err := range map[string]error{
				"disk":  VerifyIntegrity(dir, true, fingerprint, digest, nil),
				"bytes": VerifyIntegrityBytes(data, dir, true, fingerprint, digest, nil),
			} {
				t.Run(name, func(t *testing.T) {
					if err == nil || !strings.Contains(err.Error(), "unsigned bundle must not have a signer fingerprint") {
						t.Fatalf("integrity error = %v, want unsigned signer inconsistency", err)
					}
				})
			}
		})
	}
}

func TestLoadBundles_UnsignedSignerIdentityRejected(t *testing.T) {
	// Non-parallel: mutates the embedded keyring.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	setupKeyring(t, pub)

	for _, name := range []string{StandardBundleName, "pipelock-community", testBundleName} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			bundleDir := filepath.Join(dir, name)
			if err := os.MkdirAll(bundleDir, 0o750); err != nil {
				t.Fatal(err)
			}
			writeUnsignedBundle(t, bundleDir, testBundle(name, []Rule{
				testDLPRule("dlp-one", confidenceHigh, StatusStable),
				testInjectionRule("inj-one", confidenceHigh),
				testToolPoisonRule("poison-one", "description"),
			}))
			lockPath := filepath.Join(bundleDir, lockFilename)
			lock, err := ReadLockFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			lock.SignerFingerprint = KeyFingerprint(pub)
			if err := WriteLockFile(lockPath, lock); err != nil {
				t.Fatal(err)
			}

			result := LoadBundles(dir, LoadOptions{PipelockVersion: testPipelockVersion})
			if len(result.IntegrityErrors()) != 1 || !result.Degraded {
				t.Fatalf("want degraded integrity failure, got %+v", result)
			}
			if result.Errors[0].Official {
				t.Fatal("unsigned bundle error claims official status")
			}
			if len(result.Loaded)+len(result.DLP)+len(result.Injection)+len(result.ToolPoison) != 0 {
				t.Fatalf("unsigned signer identity contributed rules or loaded metadata: %+v", result)
			}
			for _, warning := range result.Warnings {
				if strings.Contains(warning, "DEGRADED: standard pack") {
					t.Fatalf("unsigned signer identity triggered official warning: %s", warning)
				}
			}
		})
	}
}

func TestMergeIntoConfig_UnsignedSignerPreservesCompiledFallback(t *testing.T) {
	// Non-parallel: mutates the embedded keyring.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	setupKeyring(t, pub)

	for _, name := range []string{StandardBundleName, "pipelock-community"} {
		t.Run(name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Rules.RulesDir = t.TempDir()
			beforeDLP := append([]config.DLPPattern(nil), cfg.DLP.Patterns...)
			beforeResponse := append([]config.ResponseScanPattern(nil), cfg.ResponseScanning.Patterns...)
			if pattern, ok := dlpPatternByName(beforeDLP, "Anthropic API Key"); !ok || !pattern.Compiled {
				t.Fatal("control: compiled standard DLP pattern is absent")
			}
			if pattern, ok := responsePatternByName(beforeResponse, "New Instructions"); !ok || !pattern.Compiled {
				t.Fatal("control: compiled standard response pattern is absent")
			}
			bundleDir := installUnsignedMergeTestBundle(t, cfg.Rules.RulesDir, name, []Rule{
				testDLPRule("dlp-one", confidenceHigh, StatusStable),
				testInjectionRule("inj-one", confidenceHigh),
			})
			lockPath := filepath.Join(bundleDir, lockFilename)
			lock, err := ReadLockFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			lock.SignerFingerprint = KeyFingerprint(pub)
			if err := WriteLockFile(lockPath, lock); err != nil {
				t.Fatal(err)
			}

			result := MergeIntoConfig(cfg, testPipelockVersion)
			if len(result.IntegrityErrors()) != 1 || len(result.Loaded) != 0 {
				t.Errorf("want rejected bundle, got %+v", result)
			}
			if result.StandardDLP == StandardSourceBundle || result.StandardResponse == StandardSourceBundle {
				t.Error("unsigned signer identity selected bundle standard sources")
			}
			if !reflect.DeepEqual(cfg.DLP.Patterns, beforeDLP) || !reflect.DeepEqual(cfg.ResponseScanning.Patterns, beforeResponse) {
				t.Error("rejected bundle changed compiled fallback patterns")
			}
		})
	}
}
