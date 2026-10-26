// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/setup"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"gopkg.in/yaml.v3"
)

func TestInstallWritePathsRefuseBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name, field, config string
	}{
		{"recorder_etc", "flight_recorder.dir", "flight_recorder: {enabled: true, dir: /etc/receipts}"},
		{"recorder_sibling", "flight_recorder.dir", "flight_recorder: {enabled: true, dir: DATA/captures}"},
		{"recorder_prefix", "flight_recorder.dir", "flight_recorder: {enabled: true, dir: DATA-evil/recorder}"},
		{"recorder_dotdot", "flight_recorder.dir", "flight_recorder: {enabled: true, dir: DATA/recorder/../../escape}"},
		{"anchor", "flight_recorder.anchor.local_log", "flight_recorder: {enabled: true, dir: DATA/recorder, anchor: {local_log: /etc/anchor.log}}"},
		{"logging", "logging.file", "logging: {output: both, file: /etc/audit.log}"},
		{"relative_logging", "logging.file", "logging: {output: file, file: audit.log}"},
		{"rules", "rules.rules_dir", "rules: {rules_dir: /etc/rules}"},
		{"baseline", "behavioral_baseline.profile_dir", "behavioral_baseline: {enabled: true, profile_dir: /etc/profiles}"},
		{"baseline_key", "behavioral_baseline.profile_dir", "behavioral_baseline: {enabled: true, profile_dir: DATA}"},
		{"learn_lock", "learn_lock.store_dir", "learn_lock: {enabled: true, store_dir: /etc/contracts}"},
		{"cache", "conductor.bundle_cache_dir", "conductor: {enabled: true, bundle_cache_dir: /etc/cache}"},
		{"queue", "conductor.durable_audit_queue_dir", "conductor: {enabled: true, bundle_cache_dir: DATA/cache, durable_audit_queue_dir: /etc/queue}"},
		{"spool", "emit.forwarder.spool_file", "emit: {forwarder: {url: 'https://sink.example', spool_file: /etc/spool}}"},
		{"cursor", "emit.forwarder.cursor_file", "emit: {forwarder: {url: 'https://sink.example', spool_file: DATA/spool, cursor_file: /etc/cursor}}"},
		{"snapshot", "dashboard_snapshot.path", "dashboard_snapshot: {enabled: true, path: /etc/snapshot}"},
		{"default_snapshot", "dashboard_snapshot.path", "flight_recorder: {enabled: false, dir: /etc/receipts}"},
		{"relative_writer", "rules.rules_dir", "rules: {rules_dir: relative-rules}"},
		{"writer_prefix", "rules.rules_dir", "rules: {rules_dir: DATA-evil/rules}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			src := filepath.Join(t.TempDir(), "pipelock.yaml")
			body := "forward_proxy: {enabled: true}\n" + strings.ReplaceAll(tc.config, "DATA", env.dataDir) + "\n"
			mustWriteFile(t, src, body)
			mutations := 0
			env.writeFile = func(string, []byte, os.FileMode) error { mutations++; return nil }
			env.mkdirAll = func(string, os.FileMode) error { mutations++; return nil }
			// Both previews and privileged installs must refuse before steps.
			for _, dryRun := range []bool{true, false} {
				err := runInstall(context.Background(), env, installOpts{dryRun: dryRun, configSource: src})
				if err == nil || !strings.Contains(err.Error(), tc.field) {
					t.Fatalf("dryRun=%v: want refusal naming %s, got %v", dryRun, tc.field, err)
				}
				if tc.field == "flight_recorder.dir" && !strings.Contains(err.Error(), "flight_recorder.dir: "+env.recorderDir()) {
					t.Errorf("missing exact remedy: %v", err)
				}
			}
			if mutations != 0 {
				t.Fatalf("refusal performed %d filesystem mutations", mutations)
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

func TestInstallWritePathsAccept(t *testing.T) {
	for i, body := range []string{
		"",
		"flight_recorder: {dir: DATA/recorder}", // default-enabled recorder
		"flight_recorder: {enabled: false, dir: /etc/unused}\ndashboard_snapshot: {enabled: false}",
		"behavioral_baseline: {enabled: false, profile_dir: /etc/unused}\nlearn_lock: {enabled: false, store_dir: /etc/unused}\nconductor: {enabled: false, bundle_cache_dir: /etc/unused}",
		"logging: {output: stdout, file: /etc/unused}\nemit: {forwarder: {spool_file: /etc/unused}}",
		"mcp_tool_policy: {quarantine_dir: /etc/unused}\nlearn: {capture_dir: /etc/unused}",
		"flight_recorder: {enabled: true, dir: DATA/recorder, anchor: {local_log: DATA/anchor.log}}\nlogging: {output: both, file: DATA/logs/audit.log}\nrules: {rules_dir: DATA/rules}\nbehavioral_baseline: {enabled: true, profile_dir: DATA/profiles}\nlearn_lock: {enabled: true, store_dir: DATA/contracts}\nconductor: {enabled: true, bundle_cache_dir: DATA/cache, durable_audit_queue_dir: DATA/queue}\nemit: {forwarder: {url: 'https://sink.example', spool_file: DATA/spool, cursor_file: DATA/cursor}}\ndashboard_snapshot: {enabled: true, path: DATA/snapshot}",
	} {
		t.Run(fmt.Sprintf("layout_%d", i), func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			src := filepath.Join(t.TempDir(), "pipelock.yaml")
			mustWriteFile(t, src, "forward_proxy: {enabled: true}\n"+strings.ReplaceAll(body, "DATA", env.dataDir)+"\n")
			if err := runInstall(context.Background(), env, installOpts{dryRun: true, configSource: src}); err != nil {
				t.Fatal(err)
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

func TestInstallWritePathsInitMigration(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		t.Run(fmt.Sprintf("dry_run_%v", dryRun), func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			binDir := installContainCommandFixtures(t)
			env.nftPath = filepath.Join(binDir, "nft")
			stat := env.stat
			env.stat = func(path string) (os.FileInfo, error) {
				if path == "/usr/local/bin/claude" {
					return stat(env.pipelockBinary)
				}
				if path == env.nftPath {
					return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
				}
				return stat(path)
			}
			mustWriteFile(t, env.caExportPath, testPEMCA(t))
			home := t.TempDir()
			lookup := env.lookupUser
			env.lookupUser = func(name string) (*user.User, error) {
				if name == env.operatorUser {
					return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: home}, nil
				}
				return lookup(name)
			}
			src := filepath.Join(home, ".config", "pipelock", "pipelock.yaml")
			cmd := setup.InitCmd()
			var initOutput bytes.Buffer
			cmd.SetOut(&initOutput)
			cmd.SetErr(&initOutput)
			cmd.SetArgs([]string{"--scan-home", home, "--output", src, "--skip-canary", "--no-auditor"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("init: %v\n%s", err, &initOutput)
			}
			before, err := os.ReadFile(filepath.Clean(src))
			if err != nil {
				t.Fatal(err)
			}
			if err := runInstall(context.Background(), env, installOpts{dryRun: dryRun, configSource: src}); err != nil {
				t.Fatalf("install: %v\n%s", err, out)
			}
			after, err := os.ReadFile(filepath.Clean(src))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("source config changed")
			}
			if dryRun {
				assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
				if _, err := os.Stat(env.dataDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("dry-run created data directory: %v", err)
				}
			} else {
				data, err := os.ReadFile(managedPipelockConfigPath(env))
				if err != nil {
					t.Fatal(err)
				}
				var cfg config.Config
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					t.Fatal(err)
				}
				if cfg.FlightRecorder.Dir != env.recorderDir() {
					t.Fatalf("recorder = %q", cfg.FlightRecorder.Dir)
				}
				if !strings.Contains(out.String(), "receipts: "+env.recorderDir()) {
					t.Fatalf("summary: %s", out)
				}
			}
		})
	}
}

func TestInstallWritePathsPermissionDeferred(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		t.Run(fmt.Sprintf("dry_run_%v", dryRun), func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			if err := os.MkdirAll(env.dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			lstat := env.lstat
			// Model the operator inspecting a service-owned 0700 directory.
			env.lstat = func(path string) (os.FileInfo, error) {
				if pathWithin(env.dataDir, path) && path != env.dataDir {
					return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrPermission}
				}
				return lstat(path)
			}
			src := filepath.Join(t.TempDir(), "pipelock.yaml")
			mustWriteFile(t, src, fmt.Sprintf("forward_proxy: {enabled: true}\nflight_recorder: {enabled: true, dir: %q}\n", env.recorderDir()))
			err := runInstall(context.Background(), env, installOpts{dryRun: dryRun, configSource: src})
			if dryRun {
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "[DEFERRED] flight_recorder.dir") {
					t.Fatalf("output = %s", out)
				}
			} else if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("privileged install must refuse unresolved paths: %v", err)
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

func TestInstallWritePathsRecorderSymlinks(t *testing.T) {
	for _, target := range []string{"outside", "captures", "missing"} {
		t.Run(target, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			if err := os.MkdirAll(env.dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(env.dataDir, target)
			if target == "outside" {
				dest = t.TempDir()
			}
			if target == "captures" {
				if err := os.MkdirAll(dest, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(dest, env.recorderDir()); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join(t.TempDir(), "pipelock.yaml")
			mustWriteFile(t, src, fmt.Sprintf("forward_proxy: {enabled: true}\nflight_recorder: {enabled: true, dir: %q}\n", env.recorderDir()))
			err := runInstall(context.Background(), env, installOpts{dryRun: true, configSource: src})
			if err == nil || !strings.Contains(err.Error(), "flight_recorder.dir") {
				t.Fatalf("got %v", err)
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

func TestInstallWritePathsSymlinkAncestor(t *testing.T) {
	for _, target := range []string{"outside", "missing", "loop", "inside"} {
		t.Run(target, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			if err := os.MkdirAll(env.dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(env.dataDir, "link")
			dest := filepath.Join(env.dataDir, "missing")
			switch target {
			case "outside":
				dest = t.TempDir()
			case "loop":
				dest = link
			case "inside":
				dest = env.dataDir
			}
			if err := os.Symlink(dest, link); err != nil {
				t.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.Rules.RulesDir = filepath.Join(link, "new", "rules")
			err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), false)
			if target == "inside" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "rules.rules_dir") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestInstallWritePathsIntegrityKeySymlink(t *testing.T) {
	for _, suffix := range []string{".integrity.key", ".integrity.key.generation", ".integrity.key.generation.lock"} {
		t.Run(suffix, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			profiles := filepath.Join(env.dataDir, "profiles")
			if err := os.MkdirAll(profiles, 0o700); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(t.TempDir(), "key")
			mustWriteFile(t, key, "private fixture")
			if err := os.Symlink(key, profiles+suffix); err != nil {
				t.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.BehavioralBaseline.Enabled = true
			cfg.BehavioralBaseline.ProfileDir = profiles
			err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), false)
			if err == nil || !strings.Contains(err.Error(), ".integrity.key") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestInstallWritePathsSpoolLockSymlink(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(env.dataDir, "spool")
	outside := filepath.Join(t.TempDir(), "lock")
	mustWriteFile(t, outside, "lock fixture")
	if err := os.Symlink(outside, spool+".lock"); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Emit.Forwarder.URL = "https://sink.example"
	cfg.Emit.Forwarder.SpoolFile = spool
	err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), false)
	if err == nil || !strings.Contains(err.Error(), "emit.forwarder.spool_file") {
		t.Fatalf("got %v", err)
	}
}

func TestInstallWritePathsAtomicParent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	inside := filepath.Join(env.dataDir, "snapshot")
	mustWriteFile(t, inside, "snapshot fixture")
	link := filepath.Join(t.TempDir(), "snapshot")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	enabled := true
	cfg.DashboardSnapshot.Enabled = &enabled
	cfg.DashboardSnapshot.Path = link
	err := requireContainWritePaths(env, cfg, managedPipelockConfigPath(env), false)
	if err == nil || !strings.Contains(err.Error(), "dashboard_snapshot.path") {
		t.Fatalf("got %v", err)
	}
}
