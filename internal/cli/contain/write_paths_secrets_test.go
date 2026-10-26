// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Private material the service only reads still lands under the recursive
// operator evidence ACL when it is kept in logs or recorder.
func TestInstallWritePathsPrivateMaterialOutsideEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		set         func(cfg *config.Config, path string)
	}{
		{"recorder_signing_key", "flight_recorder.signing_key_path", func(cfg *config.Config, path string) { cfg.FlightRecorder.SigningKeyPath = path }},
		{"mediation_signing_key", "mediation_envelope.signing_key_path", func(cfg *config.Config, path string) { cfg.MediationEnvelope.SigningKeyPath = path }},
		{"tls_ca_key", "tls_interception.ca_key", func(cfg *config.Config, path string) { cfg.TLSInterception.CAKeyPath = path }},
		{"license_file", "license_file", func(cfg *config.Config, path string) { cfg.LicenseFile = path }},
		{"commitment_keyring", "evidence_provenance.commitment_keyring_path", func(cfg *config.Config, path string) {
			cfg.EvidenceProvenance.CommitmentKeyringPath = path
		}},
		{"conductor_client_key", "conductor.client_key_path", func(cfg *config.Config, path string) { cfg.Conductor.ClientKeyPath = path }},
		{"learn_capture_dir", "learn.capture_dir", func(cfg *config.Config, path string) { cfg.Learn.CaptureDir = path }},
	} {
		for _, evidence := range []string{"logs", "recorder"} {
			t.Run(tc.name+"_"+evidence, func(t *testing.T) {
				env, _, _ := newFakeEnv(t)
				cfg := config.Defaults()
				tc.set(cfg, filepath.Join(env.dataDir, evidence, "private"))
				err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), false)
				if err == nil || !strings.Contains(err.Error(), "operator-readable evidence directory") || !strings.Contains(err.Error(), tc.field) {
					t.Fatalf("want evidence refusal naming %s, got %v", tc.field, err)
				}
			})
		}
	}
}

// A key reached through a symlink is judged by where it resolves.
func TestInstallWritePathsPrivateMaterialEvidenceAlias(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	key := filepath.Join(env.recorderDir(), "signing.key")
	mustWriteFile(t, key, "key fixture")
	link := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = link
	err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), false)
	if err == nil || !strings.Contains(err.Error(), "operator-readable evidence directory") {
		t.Fatalf("want evidence refusal, got %v", err)
	}
}

// Private material outside the evidence directories, including read-only
// locations outside the data directory, stays accepted.
func TestInstallWritePathsPrivateMaterialAccepted(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = env.recorderDir()
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	cfg.MediationEnvelope.SigningKeyPath = filepath.Join(env.configDir, "keys", "mediation-envelope-signing.key")
	cfg.LicenseFile = filepath.Join(env.configDir, "license.token")
	cfg.Learn.CaptureDir = filepath.Join(env.dataDir, "captures", "local")
	cfg.Logging.Output = "file"
	cfg.Logging.File = filepath.Join(env.logsDir(), "audit.log")
	if err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), false); err != nil {
		t.Fatalf("default private material layout refused: %v", err)
	}
}

// The full install path refuses before mutating the host, in dry run and for
// the privileged install alike.
func TestInstallWritePathsPrivateMaterialRefusedBeforeMutation(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	src := managedPipelockConfigPath(env)
	key := filepath.Join(env.recorderDir(), "signing.key")
	mustWriteFile(t, src, fmt.Sprintf("forward_proxy: {enabled: true}\nflight_recorder: {enabled: true, dir: %q, signing_key_path: %q}\n", env.recorderDir(), key))
	for _, dryRun := range []bool{true, false} {
		err := runInstall(context.Background(), env, installOpts{dryRun: dryRun})
		if err == nil || !strings.Contains(err.Error(), "flight_recorder.signing_key_path") {
			t.Fatalf("dryRun=%v: want signing key refusal, got %v", dryRun, err)
		}
	}
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
}

// An unprivileged dry run cannot resolve inside a 0700 data directory. Material
// written inside an evidence directory is still refused by its lexical
// location; other unreadable material is deferred to the privileged install.
func TestInstallWritePathsPrivateMaterialPermissionDeferred(t *testing.T) {
	for _, tc := range []struct {
		name, dir string
		refuse    bool
	}{
		{"inside_recorder", "recorder", true},
		{"outside_evidence", "keys", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			if err := os.MkdirAll(env.dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			lstat := env.lstat
			env.lstat = func(path string) (os.FileInfo, error) {
				if pathWithin(env.dataDir, path) && path != env.dataDir {
					return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrPermission}
				}
				return lstat(path)
			}
			key := filepath.Join(env.dataDir, tc.dir, "signing.key")
			src := filepath.Join(t.TempDir(), "pipelock.yaml")
			mustWriteFile(t, src, fmt.Sprintf("forward_proxy: {enabled: true}\nflight_recorder: {enabled: false, signing_key_path: %q}\n", key))
			err := runInstall(context.Background(), env, installOpts{dryRun: true, configSource: src})
			if tc.refuse {
				if err == nil || !strings.Contains(err.Error(), "operator-readable evidence directory") {
					t.Fatalf("want evidence refusal, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "[DEFERRED] flight_recorder.signing_key_path") {
					t.Fatalf("output = %s", out)
				}
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

// With a symlinked data directory, unresolvable material spelled under the
// configured data directory is still matched against the evidence directories.
func TestInstallWritePathsPrivateMaterialSymlinkedDataDirFallback(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	env.dataDir = filepath.Join(t.TempDir(), "pipelock")
	if err := os.Symlink(target, env.dataDir); err != nil {
		t.Fatal(err)
	}
	lstat := env.lstat
	env.lstat = func(path string) (os.FileInfo, error) {
		if pathWithin(env.dataDir, path) && path != env.dataDir {
			return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrPermission}
		}
		return lstat(path)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(env.dataDir, "recorder", "signing.key")
	err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), true)
	if err == nil || !strings.Contains(err.Error(), "operator-readable evidence directory") {
		t.Fatalf("want evidence refusal, got %v", err)
	}
}
