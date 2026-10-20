// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDisplayAbsentSocketRuntimeDiagnostics(t *testing.T) {
	for _, scenario := range []string{"runtime mode", "runtime owner", "runtime group", "missing rule", "drifted rule"} {
		t.Run(scenario, func(t *testing.T) {
			install, _ := displayRuntimeTestEnv(t)
			if _, err := stepProvisionDisplayRuntime().apply(context.Background(), install); err != nil {
				t.Fatal(err)
			}
			install.displayConfig = config.ContainmentDisplay{Backend: "xvnc"}
			if err := os.WriteFile(install.displayUnitPath, []byte(renderAgentDisplayUnit(install)), 0o600); err != nil {
				t.Fatal(err)
			}
			if scenario == "runtime mode" {
				if err := os.Chmod(filepath.Dir(install.rfbSocketPath), 0o755); err != nil { //nolint:gosec // Unsafe runtime fixture must be refused.
					t.Fatal(err)
				}
			}
			stat := func(path string) (os.FileInfo, error) {
				if path == install.rfbSocketPath || (scenario == "missing rule" && path == install.displayTmpfilesPath) {
					return nil, os.ErrNotExist
				}
				if path == filepath.Dir(install.rfbSocketPath) {
					switch scenario {
					case "runtime owner":
						return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(123, 456)}, nil
					case "runtime group":
						return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(0, 999)}, nil
					}
				}
				return install.lstat(path)
			}
			read := func(path string) ([]byte, error) {
				if scenario == "drifted rule" && path == install.displayTmpfilesPath {
					return []byte(displayUnitMarker + "\nd /run/wrong 0755 root root - -\n"), nil
				}
				return install.readFile(path)
			}
			probe := &probeEnv{configPath: managedPipelockConfigPath(install), displayUnitPath: install.displayUnitPath, displayTmpfilesPath: install.displayTmpfilesPath, rfbSocketPath: install.rfbSocketPath, agentUserName: install.agentUserName, lookupUser: install.lookupUser, readFile: read, lstat: stat}
			doctor := &doctorEnv{configPath: probe.configPath, displayTmpfilesPath: probe.displayTmpfilesPath, rfbSocketPath: probe.rfbSocketPath, agentUserName: probe.agentUserName, lookupUser: probe.lookupUser, lstat: stat, readFile: read, stat: func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o755}, nil }}
			got := checkDoctorDisplayRFB(context.Background(), doctor)
			status, detail := probeAgentDisplayRFB(context.Background(), probe)
			want := displayRuntimeRepair(install.rfbSocketPath)
			if !strings.HasPrefix(scenario, "runtime ") {
				want = "restore a regular root:root 0600 managed rule at " + install.displayTmpfilesPath + "; rerun contain install"
			}
			if got.status != statusFail || status != statusFail || got.remediation != want || !strings.Contains(detail, want) {
				t.Fatalf("doctor=%+v verify=(%s,%s), want shared remedy %q", got, status, detail, want)
			}
			if strings.Contains(got.remediation+detail, "systemd-tmpfiles --create") {
				t.Fatal("unsafe existing runtime or unverified rule offered tmpfiles repair")
			}
		})
	}
}

func TestDisplayFreshRollbackRuntimeCleanupRefusalRemovesUnit(t *testing.T) {
	for _, scenario := range []string{"nonempty runtime", "runtime removal denied"} {
		t.Run(scenario, func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			prepareMigrationAuthority(t, env)
			env.xvncPath = filepath.Join(t.TempDir(), "Xvnc")
			if err := os.WriteFile(env.xvncPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			runtime := filepath.Dir(env.rfbSocketPath)
			oldRemove := env.removeFile
			env.removeFile = func(path string) error {
				if scenario == "runtime removal denied" && path == runtime {
					return os.ErrPermission
				}
				return oldRemove(path)
			}
			oldRun := env.runCmd
			enabled, rolling, restarted := false, false, false
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name == "systemd-tmpfiles" {
					return oldRun(ctx, name, args...)
				}
				if name == "getfacl" {
					return "user::rwx\ngroup::r-x\nother::---\n", 0, nil
				}
				if name != "systemctl" {
					return "", 0, nil
				}
				switch args[0] {
				case "is-active":
					return systemctlInactive, 3, nil
				case "is-enabled":
					return "disabled", 1, nil
				case "enable":
					enabled = true
					if rolling {
						t.Error("fresh unit enabled during rollback")
					}
					rolling = true
					if scenario == "nonempty runtime" {
						if err := os.WriteFile(filepath.Join(runtime, "stale.socket"), nil, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					return "display start failed", 1, nil
				case "disable":
					enabled = false
				case "start", "restart":
					restarted = true
				}
				return "", 0, nil
			}
			_, err := runSteps(context.Background(), env, io.Discard, []step{stepProvisionDisplay()})
			want := "preserve nonempty display runtime directory"
			if scenario == "runtime removal denied" {
				want = os.ErrPermission.Error()
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("runtime cleanup refusal was not reported: %v", err)
			}
			if enabled || restarted {
				t.Fatalf("fresh display left enabled=%v restarted=%v", enabled, restarted)
			}
			for _, path := range []string{env.displayUnitPath, displayAuthorityPath(env), env.displayTmpfilesPath} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("fresh install residue at %s: %v", path, err)
				}
			}
			if _, err := os.Stat(runtime); err != nil {
				t.Fatalf("refused runtime cleanup still removed directory: %v", err)
			}
		})
	}
}
