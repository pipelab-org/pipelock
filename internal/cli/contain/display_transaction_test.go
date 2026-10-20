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

func TestDisplayRuntimeTransactionRestoresBeforeRestart(t *testing.T) {
	for _, scenario := range []string{"disable then later failure", "xvfb then later failure", "start failure", "rule restore failure", "prior inactive", "unmanaged unit", "xvnc missing runtime", "recreated bind drift", "prior disabled", "unmanaged enabled then failure", "unchanged runtime", "rollback stop failure"} {
		t.Run(scenario, func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			prepareMigrationAuthority(t, env)
			env.displayConfig = config.ContainmentDisplay{Backend: "xvnc"}
			env.displayNumber = 99
			if scenario != "xvnc missing runtime" && scenario != "recreated bind drift" {
				runtime := filepath.Dir(env.rfbSocketPath)
				if err := os.MkdirAll(runtime, 0o730); err != nil { //nolint:gosec // Existing runtime contract fixture.
					t.Fatal(err)
				}
				if err := os.Chmod(runtime, 0o730); err != nil { //nolint:gosec // Existing runtime contract fixture.
					t.Fatal(err)
				}
			}
			priorUnit := renderAgentDisplayUnit(env)
			if strings.HasPrefix(scenario, "unmanaged") {
				priorUnit = "[Service]\nExecStart=/usr/bin/true\n"
			}
			if err := os.WriteFile(env.displayUnitPath, []byte(priorUnit), 0o600); err != nil {
				t.Fatal(err)
			}
			priorRule := append(renderDisplayRuntimeRule(env.rfbSocketPath), []byte("# Prior managed bytes preserved on rollback.\n")...)
			if scenario == "unchanged runtime" {
				priorRule = renderDisplayRuntimeRule(env.rfbSocketPath)
			}
			if err := os.MkdirAll(filepath.Dir(env.displayTmpfilesPath), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(env.displayTmpfilesPath, priorRule, 0o600); err != nil {
				t.Fatal(err)
			}
			backend := "xvnc"
			enabled := "false"
			if scenario == "xvnc missing runtime" || scenario == "recreated bind drift" {
				enabled = "true"
			}
			if scenario == "xvfb then later failure" || scenario == "start failure" || scenario == "unmanaged enabled then failure" {
				backend = "xvfb"
				enabled = "true"
			}
			if err := os.WriteFile(managedPipelockConfigPath(env), []byte("containment:\n  display:\n    enabled: "+enabled+"\n    backend: "+backend+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			env.xvfbPath = filepath.Join(filepath.Dir(env.displayUnitPath), "Xvfb")
			if err := os.WriteFile(env.xvfbPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			if scenario == "xvnc missing runtime" || scenario == "recreated bind drift" {
				env.xvncPath = env.xvfbPath
				oldStat := env.lstat
				env.lstat = func(p string) (os.FileInfo, error) {
					if p == env.rfbSocketPath || p == displaySocketPath(99) {
						return fakeFileInfo{mode: os.ModeSocket | 0o600, sys: fakeFileSysWithOwner(123, 456)}, nil
					}
					return oldStat(p)
				}
				// The X socket uses its existing 0700 contract.
				socketStat := env.lstat
				env.lstat = func(p string) (os.FileInfo, error) {
					if p == displaySocketPath(99) {
						return fakeFileInfo{mode: os.ModeSocket | 0o700, sys: fakeFileSysWithOwner(123, 456)}, nil
					}
					return socketStat(p)
				}
			}
			oldRun := env.runCmd
			rolling, stopped, restarted, restoredEnable := false, false, false, false
			env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				if name == "systemd-tmpfiles" {
					return oldRun(context.Background(), name, args...)
				}
				if name == "getfacl" {
					return "user::rwx\ngroup::r-x\nother::---\n", 0, nil
				}
				if name != "systemctl" {
					return "", 0, nil
				}
				switch args[0] {
				case "is-enabled":
					if scenario == "prior disabled" {
						return "disabled", 1, nil
					}
					return "enabled", 0, nil
				case "is-active":
					if stopped || scenario == "prior inactive" {
						return "inactive", 3, nil
					}
					return "active", 0, nil
				case "stop", "disable":
					if scenario == "rollback stop failure" && rolling && args[0] == "stop" {
						return "stop failed", 1, nil
					}
					stopped = true
				case "enable":
					if rolling {
						restoredEnable = true
					}
					if scenario == "start failure" && len(args) > 1 && args[1] == "--now" && !rolling {
						rolling = true
						return "start failed", 1, nil
					}
				case "start", "restart":
					if rolling {
						if !stopped {
							t.Error("display was not stopped before rollback")
						}
						body, err := os.ReadFile(env.displayTmpfilesPath)
						if err != nil || string(body) != string(priorRule) {
							t.Errorf("display restarted before prior rule restored: %q %v", body, err)
						}
						if _, err := os.Stat(filepath.Dir(env.rfbSocketPath)); err != nil {
							t.Errorf("restored display bind source missing: %v", err)
						}
						restarted = true
					}
				}
				return "", 0, nil
			}
			oldWrite := env.writeFile
			env.writeFile = func(p string, b []byte, m os.FileMode) error {
				if scenario == "rule restore failure" && rolling && p == env.displayTmpfilesPath {
					return os.ErrPermission
				}
				return oldWrite(p, b, m)
			}
			var selected []step
			for _, s := range installSteps(installOpts{}) {
				if s.name == "provision-agent-display" {
					selected = append(selected, s)
				}
			}
			selected = append(selected, step{name: "later-failure", apply: func(context.Context, *installEnv) (bool, error) {
				if scenario == "recreated bind drift" {
					if err := os.Chmod(filepath.Dir(env.rfbSocketPath), 0o750); err != nil { //nolint:gosec // Directory drift must prevent restart.
						t.Fatal(err)
					}
				}
				rolling = true
				return false, errors.New("later failure")
			}})
			_, err := runSteps(context.Background(), env, io.Discard, selected)
			if err == nil {
				t.Fatal("failure accepted")
			}
			if scenario == "unmanaged unit" {
				body, readErr := os.ReadFile(env.displayUnitPath)
				if readErr != nil || string(body) != priorUnit || stopped || restarted {
					t.Fatalf("unmanaged unit changed: stopped=%v restarted=%v read=%v", stopped, restarted, readErr)
				}

			} else if scenario == "rollback stop failure" {
				if restarted || !strings.Contains(err.Error(), "stop failed") {
					t.Fatalf("stop failure did not hold restart: %v restarted=%v", err, restarted)
				}
				return
			} else if scenario == "rule restore failure" {
				if restarted || !stopped || !strings.Contains(err.Error(), "restore display runtime before restarting display") {
					t.Fatalf("unsafe restore failure: stopped=%v restarted=%v err=%v", stopped, restarted, err)
				}
				return

			} else if scenario == "recreated bind drift" {
				if restarted || !stopped || !strings.Contains(err.Error(), "want 0730") {
					t.Fatalf("drifted bind source restarted: stopped=%v restarted=%v err=%v", stopped, restarted, err)
				}
				body, readErr := os.ReadFile(env.displayTmpfilesPath)
				if readErr != nil || string(body) != string(priorRule) {
					t.Fatalf("prior rule not restored before refusing restart: %q %v", body, readErr)
				}
				return
			} else if scenario == "prior inactive" {
				if restarted {
					t.Fatal("previously inactive display restarted")
				}
			} else if !restarted {
				t.Fatalf("prior active display not restarted: %v", err)
			}
			if scenario == "prior disabled" && restoredEnable {
				t.Fatal("previously disabled display enabled during rollback")
			}
			body, readErr := os.ReadFile(env.displayTmpfilesPath)
			if readErr != nil || string(body) != string(priorRule) {
				t.Fatalf("prior rule lost: %q %v", body, readErr)
			}
			unit, readErr := os.ReadFile(env.displayUnitPath)
			if readErr != nil || string(unit) != priorUnit {
				t.Fatalf("prior unit lost: %q %v", unit, readErr)
			}
		})
	}
}

func TestDisplayRuntimeTransactionFreshFailureCleansRuntime(t *testing.T) {
	for _, phase := range []string{"runtime", "discovery", "start"} {
		t.Run(phase, func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			prepareMigrationAuthority(t, env)

			switch phase {
			case "runtime":
				env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "tmpfiles failed", 1, nil }
			case "discovery":
				env.xvncPath = filepath.Join(t.TempDir(), "missing-Xvnc")
				env.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
			default:
				env.xvncPath = filepath.Join(t.TempDir(), "Xvnc")
				if err := os.WriteFile(env.xvncPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				oldRun := env.runCmd
				env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
					if name == "systemd-tmpfiles" {
						return oldRun(ctx, name, args...)
					}
					if name == "getfacl" {
						return "user::rwx\ngroup::r-x\nother::---\n", 0, nil
					}
					if name == "systemctl" {
						if args[0] == "is-active" {
							return "inactive", 3, nil
						}
						if args[0] == "is-enabled" {
							return "disabled", 1, nil
						}
						if args[0] == "enable" && len(args) > 1 && args[1] == "--now" {
							return "start failed", 1, nil
						}
					}
					return "", 0, nil
				}
			}
			_, err := runSteps(context.Background(), env, io.Discard, []step{stepProvisionDisplay()})
			if err == nil {
				t.Fatal("display failure accepted")
			}
			for _, p := range []string{env.displayTmpfilesPath, filepath.Dir(env.rfbSocketPath), env.displayUnitPath, displayAuthorityPath(env)} {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("fresh runtime residue at %s: %v", p, err)
				}
			}
		})
	}
}

func TestDisplayRuntimeTransactionDisabledNoChanges(t *testing.T) {
	env, _ := displayRuntimeTestEnv(t)
	if err := os.WriteFile(managedPipelockConfigPath(env), []byte("containment:\n  display:\n    enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "inactive", 3, nil }
	changed, err := stepProvisionDisplay().apply(context.Background(), env)
	if err != nil || changed {
		t.Fatalf("disabled installation changed=%v err=%v", changed, err)
	}
}
