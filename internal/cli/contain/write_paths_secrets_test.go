// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
		{"rekor_key", "flight_recorder.anchor.rekor_key_path", func(cfg *config.Config, path string) { cfg.FlightRecorder.Anchor.RekorKeyPath = path }},
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

// The Rekor entry-signing key is private material and is hidden from the agent
// like the other configured signing keys.
func TestConfiguredSecretPathsHideRekorKey(t *testing.T) {
	cfg := &config.Config{}
	cfg.FlightRecorder.Anchor.RekorKeyPath = "keys/rekor-entry.key"
	_, optional := configuredSecretPaths(cfg, "/etc/pipelock")
	if !slices.Contains(optional, "/etc/pipelock/keys/rekor-entry.key") {
		t.Fatalf("rekor key not hidden: %v", optional)
	}
}

// A relative path that config.Load does not rebase opens from the service
// working directory, /, so that spelling is checked as well as the
// config-relative one.
func TestInstallWritePathsPrivateMaterialRelativeToServiceRoot(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	cfg := config.Defaults()
	rel := strings.TrimPrefix(filepath.Join(env.recorderDir(), "rekor-entry.key"), string(os.PathSeparator))
	cfg.FlightRecorder.Anchor.RekorKeyPath = rel
	err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), false)
	if err == nil || !strings.Contains(err.Error(), "flight_recorder.anchor.rekor_key_path") || !strings.Contains(err.Error(), "operator-readable evidence directory") {
		t.Fatalf("want evidence refusal for service-root relative path, got %v", err)
	}
}

// A path outside the evidence tree can reach a key inside it through an
// ancestor that the installer cannot inspect. A real install must not grant
// the evidence ACL when it cannot determine where that input lives.
func TestInstallWritePathsPrivateMaterialUnreadableAlias(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged process for the real permission failure")
	}
	for _, dryRun := range []bool{true, false} {
		t.Run(fmt.Sprintf("dry_run_%v", dryRun), func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			key := filepath.Join(env.recorderDir(), "signing.key")
			mustWriteFile(t, key, "private key fixture")
			privateDir := filepath.Join(t.TempDir(), "unreadable")
			if err := os.Mkdir(privateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(privateDir, "keys")
			if err := os.Symlink(env.recorderDir(), alias); err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(alias, "signing.key")
			resolved, err := filepath.EvalSymlinks(input)
			if err != nil || resolved != key {
				t.Fatalf("alias does not reach evidence key: %q, %v", resolved, err)
			}
			mustWriteFile(t, managedPipelockConfigPath(env), fmt.Sprintf("forward_proxy: {enabled: true}\nflight_recorder: {enabled: true, dir: %q, signing_key_path: %q}\n", env.recorderDir(), input))
			if err := os.Chmod(privateDir, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(privateDir, 0o700); err != nil { //nolint:gosec // G302: restore directory traversal for test cleanup.
					t.Error(err)
				}
			})
			if _, err := os.Lstat(input); !errors.Is(err, os.ErrPermission) {
				t.Fatalf("expected real permission failure, got %v", err)
			}
			if !dryRun {
				err = requireContainForwardProxy(env, managedPipelockConfigPath(env), managedPipelockConfigPath(env), installOpts{})
				if !errors.Is(err, os.ErrPermission) {
					t.Fatalf("private-input preflight accepted an unreadable evidence alias: %v", err)
				}
			}
			err = runInstall(context.Background(), env, installOpts{dryRun: dryRun})
			if dryRun {
				if err != nil || !strings.Contains(out.String(), "[DEFERRED] flight_recorder.signing_key_path") {
					t.Fatalf("expected deferred preview, got %v\n%s", err, out)
				}
			} else if !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "flight_recorder.signing_key_path") {
				t.Fatalf("unresolved private input must refuse install, got %v", err)
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

func TestInstallWritePathsPrivateMaterialResolutionErrors(t *testing.T) {
	for _, rootFailure := range []bool{false, true} {
		for _, dryRun := range []bool{false, true} {
			for _, permission := range []bool{false, true} {
				t.Run(fmt.Sprintf("root_%v_dry_%v_permission_%v", rootFailure, dryRun, permission), func(t *testing.T) {
					env, _, out := newFakeEnv(t)
					cfg := &config.Config{}
					key := filepath.Join(env.configDir, "keys", "signing.key")
					cfg.FlightRecorder.SigningKeyPath = key
					failure := errors.New("unresolved symlink")
					if permission {
						failure = os.ErrPermission
					}
					lstat := env.lstat
					env.lstat = func(path string) (os.FileInfo, error) {
						if (rootFailure && path == env.dataDir) || (!rootFailure && path == key) {
							return nil, &os.PathError{Op: "lstat", Path: path, Err: failure}
						}
						return lstat(path)
					}
					err := requirePrivateMaterialOutsideEvidence(env, cfg, managedPipelockConfigPath(env), dryRun)
					if dryRun && permission {
						if err != nil || !strings.Contains(out.String(), "[DEFERRED]") {
							t.Fatalf("want deferred preview, got %v\n%s", err, out)
						}
					} else if !errors.Is(err, failure) {
						t.Fatalf("want resolution refusal, got %v", err)
					}
				})
			}
		}
	}
}
