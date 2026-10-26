// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestUpgradeUnitRollback(t *testing.T) {
	for _, stage := range []string{"marker", "timeout", "timeout-after-write", "daemon-reload", "restart", "post-verify"} {
		t.Run(stage, func(t *testing.T) {
			env := testUpgradeEnv(t)
			original, err := os.ReadFile(env.unitPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(env.unitPath, 0o640); err != nil { // #nosec G302 -- fixture mode must differ from the 0600 writer default to prove rollback restores the original mode.
				t.Fatal(err)
			}
			before, err := os.Stat(env.unitPath)
			if err != nil {
				t.Fatal(err)
			}
			uid, _ := fileOwnerUID(before)
			gid, _ := fileOwnerGID(before)
			failure := errors.New("injected upgrade failure")
			failed := false
			unitWrites, unitChowns, rollbackReloads := 0, 0, 0
			env.chmod = func(path string, mode os.FileMode) error {
				if path == env.unitPath {
					return os.Chmod(path, mode)
				}
				return nil
			}
			env.chown = func(path string, owner, group int) error {
				if path != env.unitPath {
					return nil
				}
				unitChowns++
				if owner != int(uid) || group != int(gid) {
					t.Errorf("restored owner = %d:%d, want %d:%d", owner, group, uid, gid)
				}
				return os.Chown(path, owner, group)
			}
			env.writeFile = func(path string, data []byte, mode os.FileMode) error {
				if path == env.unitPath {
					unitWrites++
					if !failed && ((stage == "marker" && unitWrites == 1) ||
						((stage == "timeout" || stage == "timeout-after-write") && unitWrites == 2)) {
						failed = true
						if stage == "timeout-after-write" {
							if err := writeFileAtomic(path, data, mode); err != nil {
								t.Fatal(err)
							}
						}
						return failure
					}
				}
				return writeFileAtomic(path, data, mode)
			}
			succeed := successRunCmd(env, []byte("new-binary-content"))
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if !failed && ((name == "systemctl" && args[0] == stage) ||
					(stage == "post-verify" && name == env.pipelockTarget && args[0] == "contain")) {
					failed = true
					return "", 1, failure
				}
				if failed && name == "systemctl" {
					got, err := os.ReadFile(env.unitPath)
					if err != nil || !bytes.Equal(got, original) {
						t.Errorf("unit before rollback %s = %q, %v; want original %q", args[0], got, err, original)
					}
					if args[0] == "daemon-reload" {
						rollbackReloads++
						if unitChowns != 1 {
							t.Errorf("reload before ownership restore: chowns = %d", unitChowns)
						}
					}
				}
				return succeed(ctx, name, args...)
			}
			err = runUpgrade(context.Background(), env, upgradeOpts{})
			if !failed || !errors.Is(err, failure) {
				t.Fatalf("upgrade error = %v, want injected failure (reached=%t)", err, failed)
			}
			got, err := os.ReadFile(env.unitPath)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("unit after rollback = %q, %v; want original %q", got, err, original)
			}
			after, err := os.Stat(env.unitPath)
			if err != nil {
				t.Fatal(err)
			}
			if after.Mode() != before.Mode() {
				t.Errorf("restored mode = %v, want %v", after.Mode(), before.Mode())
			}
			afterUID, _ := fileOwnerUID(after)
			afterGID, _ := fileOwnerGID(after)
			if afterUID != uid || afterGID != gid {
				t.Errorf("restored owner = %d:%d, want %d:%d", afterUID, afterGID, uid, gid)
			}
			if rollbackReloads != 1 {
				t.Errorf("rollback daemon-reloads = %d, want 1", rollbackReloads)
			}
		})
	}
}

func TestUpgradeUnitRollbackFailureJoinsOriginalError(t *testing.T) {
	for _, stage := range []string{"write", "ownership", "mode", "reload-exec", "reload-exit"} {
		t.Run(stage, func(t *testing.T) {
			env := testUpgradeEnv(t)
			originalFailure := errors.New("injected restart failure")
			restoreFailure := errors.New("injected restore failure")
			rollingBack := false
			env.writeFile = func(path string, data []byte, mode os.FileMode) error {
				if rollingBack && path == env.unitPath && stage == "write" {
					return restoreFailure
				}
				return writeFileAtomic(path, data, mode)
			}
			env.chown = func(path string, _, _ int) error {
				if path == env.unitPath && stage == "ownership" {
					return restoreFailure
				}
				return nil
			}
			env.chmod = func(path string, _ os.FileMode) error {
				if path == env.unitPath && stage == "mode" {
					return restoreFailure
				}
				return nil
			}
			succeed := successRunCmd(env, []byte("new-binary-content"))
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name == "systemctl" && args[0] == "restart" && !rollingBack {
					rollingBack = true
					return "", 1, originalFailure
				}
				if rollingBack && name == "systemctl" && args[0] == "daemon-reload" {
					if stage == "reload-exec" {
						return "", 1, restoreFailure
					}
					if stage == "reload-exit" {
						return "", 1, nil
					}
				}
				return succeed(ctx, name, args...)
			}
			err := runUpgrade(context.Background(), env, upgradeOpts{})
			if !errors.Is(err, originalFailure) || !errors.Is(err, errUpgradeRollback) {
				t.Fatalf("error must retain original and rollback failures: %v", err)
			}
			if stage != "reload-exit" && !errors.Is(err, restoreFailure) {
				t.Errorf("restore error missing: %v", err)
			}
			if stage == "reload-exit" && !strings.Contains(err.Error(), "daemon-reload exited 1") {
				t.Errorf("reload exit status missing: %v", err)
			}
		})
	}
}

func TestUpgradeUnitSnapshotFailureDoesNotWriteUnit(t *testing.T) {
	for _, stage := range []string{"inspect", "read", "ownership"} {
		t.Run(stage, func(t *testing.T) {
			env := testUpgradeEnv(t)
			failure := errors.New("injected snapshot failure")
			origLstat, origRead := env.lstat, env.readFile
			env.lstat = func(path string) (os.FileInfo, error) {
				if path == env.unitPath {
					if stage == "inspect" {
						return nil, failure
					}
					if stage == "ownership" {
						return containFileInfo{name: "pipelock.service", mode: 0o640}, nil
					}
				}
				return origLstat(path)
			}
			env.readFile = func(path string) ([]byte, error) {
				if path == env.unitPath && stage == "read" {
					return nil, failure
				}
				return origRead(path)
			}
			env.writeFile = func(path string, data []byte, mode os.FileMode) error {
				if path == env.unitPath {
					t.Error("unit written without a usable snapshot")
				}
				return writeFileAtomic(path, data, mode)
			}
			env.runCmd = successRunCmd(env, []byte("new-binary-content"))
			err := runUpgrade(context.Background(), env, upgradeOpts{})
			if !errors.Is(err, errUpgradeConfig) {
				t.Fatalf("snapshot failure not returned: %v", err)
			}
			if stage != "ownership" && !errors.Is(err, failure) {
				t.Errorf("snapshot error missing: %v", err)
			}
			if stage == "ownership" && !strings.Contains(err.Error(), "ownership") {
				t.Errorf("missing ownership error: %v", err)
			}
		})
	}
}

func TestUpgradeUnitWithBOM(t *testing.T) {
	for _, body := range []string{
		"\ufeff[Service]\nExecStart=/usr/bin/true\n",
		"\ufeff[Unit]\nDescription=Proxy\n[Service]\nExecStart=/usr/bin/true\n",
	} {
		t.Run(body, func(t *testing.T) {
			env := testUpgradeEnv(t)
			if err := writeFileAtomic(env.unitPath, []byte(body), 0o640); err != nil {
				t.Fatal(err)
			}
			restore, err := upgradeMigrateUnit(env)
			if err != nil || restore == nil {
				t.Fatalf("migration = %v, restore present=%t", err, restore != nil)
			}
			got, err := os.ReadFile(env.unitPath)
			if err != nil {
				t.Fatal(err)
			}
			marker := "Environment=" + config.ContainmentManagedEnvKey + "=" + config.ContainmentManagedEnvValue
			if !bytes.HasPrefix(got, []byte("\ufeff")) || !unitHasActiveContainmentMarker(string(got), marker) ||
				!unitServiceSetsDirective(string(got), "TimeoutStopSec") {
				t.Fatalf("BOM or migrated directives missing: %q", got)
			}
			if err := restore(); err != nil {
				t.Fatal(err)
			}
			got, err = os.ReadFile(env.unitPath)
			if err != nil || string(got) != body {
				t.Fatalf("BOM unit not restored byte-for-byte: %q, %v", got, err)
			}
		})
	}
}

func TestUpgradeUnitWithLaterBOM(t *testing.T) {
	marker := "Environment=" + config.ContainmentManagedEnvKey + "=" + config.ContainmentManagedEnvValue
	for _, body := range []string{
		"[Unit]\nDescription=Proxy\n\ufeff[Service]\nExecStart=/usr/bin/true\n",
		"[Service]\nExecStart=/usr/bin/true\n\ufeff[Unit]\n" + marker + "\nTimeoutStopSec=600\n",
	} {
		t.Run(body, func(t *testing.T) {
			env := testUpgradeEnv(t)
			if err := writeFileAtomic(env.unitPath, []byte(body), 0o640); err != nil {
				t.Fatal(err)
			}
			restore, err := upgradeMigrateUnit(env)
			if err != nil || restore == nil {
				t.Fatalf("migration = %v, restore present=%t", err, restore != nil)
			}
			want := strings.Replace(body, "[Service]\n", "[Service]\n"+wantStopTimeoutDirective()+"\n"+marker+"\n", 1)
			got, err := os.ReadFile(env.unitPath)
			if err != nil || string(got) != want {
				t.Fatalf("migrated unit = %q, %v; want %q", got, err, want)
			}
			if err := restore(); err != nil {
				t.Fatal(err)
			}
			got, err = os.ReadFile(env.unitPath)
			if err != nil || string(got) != body {
				t.Fatalf("restored unit = %q, %v; want %q", got, err, body)
			}
		})
	}
}

func TestUpgradeUnitBOMIsSkippedOnlyOnce(t *testing.T) {
	marker := "Environment=" + config.ContainmentManagedEnvKey + "=" + config.ContainmentManagedEnvValue
	for _, tt := range []struct {
		body string
		want bool
	}{
		{"[Service]\n\ufeff" + marker + "\n", true},
		{"\ufeff[Service]\n\ufeff" + marker + "\n", false},
	} {
		t.Run(tt.body, func(t *testing.T) {
			if got := unitHasActiveContainmentMarker(tt.body, marker); got != tt.want {
				t.Fatalf("active marker = %t, want %t", got, tt.want)
			}
		})
	}
}

type upgradeUnitOwnerInfo struct {
	os.FileInfo
}

func (upgradeUnitOwnerInfo) Sys() any { return fakeFileSysWithOwner(1234, 2345) }

func TestUpgradeUnitRestoresCapturedOwnership(t *testing.T) {
	env := testUpgradeEnv(t)
	info, err := os.Lstat(env.unitPath)
	if err != nil {
		t.Fatal(err)
	}
	env.lstat = func(string) (os.FileInfo, error) {
		return upgradeUnitOwnerInfo{info}, nil
	}
	restore, err := upgradeMigrateUnit(env)
	if err != nil || restore == nil {
		t.Fatalf("migration = %v, restore present=%t", err, restore != nil)
	}
	called := false
	env.chown = func(path string, uid, gid int) error {
		called = true
		if path != env.unitPath || uid != 1234 || gid != 2345 {
			t.Errorf("chown(%q, %d, %d), want captured unit owner 1234:2345", path, uid, gid)
		}
		return nil
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("captured ownership was not restored")
	}
}

func TestUpgradeUnitWithoutMigrationIsUntouched(t *testing.T) {
	for _, failRestart := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[failRestart], func(t *testing.T) {
			env := testUpgradeEnv(t)
			unit := []byte("[Service]\nEnvironment=" + config.ContainmentManagedEnvKey + "=" + config.ContainmentManagedEnvValue + "\nTimeoutStopSec=10min\n")
			if err := writeFileAtomic(env.unitPath, unit, 0o640); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(env.unitPath)
			if err != nil {
				t.Fatal(err)
			}
			env.writeFile = func(path string, data []byte, mode os.FileMode) error {
				if path == env.unitPath {
					t.Error("unit needing no migration was rewritten")
				}
				return writeFileAtomic(path, data, mode)
			}
			succeed := successRunCmd(env, []byte("new-binary-content"))
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if failRestart && name == "systemctl" && args[0] == "restart" {
					return "", 1, nil
				}
				return succeed(ctx, name, args...)
			}
			err = runUpgrade(context.Background(), env, upgradeOpts{})
			if (err != nil) != failRestart {
				t.Fatalf("upgrade error = %v, want failure=%t", err, failRestart)
			}
			after, err := os.Stat(env.unitPath)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(env.unitPath)
			if err != nil || !bytes.Equal(got, unit) || before.Mode() != after.Mode() || !os.SameFile(before, after) {
				t.Fatalf("unit changed despite needing no migration: %q, %v", got, err)
			}
		})
	}
}
