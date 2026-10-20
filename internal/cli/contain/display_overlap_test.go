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
)

func TestDisplayOverlappingInstallPreservesAdoptedRule(t *testing.T) {
	first, _ := displayRuntimeTestEnv(t)
	prepareMigrationAuthority(t, first)
	second := *first
	second.xvncPath = filepath.Join(filepath.Dir(first.displayUnitPath), "Xvnc")
	if err := os.WriteFile(second.xvncPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oldStat := first.lstat
	second.lstat = func(path string) (os.FileInfo, error) {
		switch path {
		case second.rfbSocketPath:
			return fakeFileInfo{mode: os.ModeSocket | 0o600, sys: fakeFileSysWithOwner(123, 456)}, nil
		case displaySocketPath(99):
			return fakeFileInfo{mode: os.ModeSocket | 0o700, sys: fakeFileSysWithOwner(123, 456)}, nil
		default:
			return oldStat(path)
		}
	}
	first.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	active := false
	tmpfiles := first.runCmd
	run := func(ctx context.Context, name string, args ...string) (string, int, error) {
		if name == "systemd-tmpfiles" {
			return tmpfiles(ctx, name, args...)
		}
		if name == "getfacl" {
			return "user::rwx\ngroup::r-x\nother::---\n", 0, nil
		}
		if name == "systemctl" {
			switch args[0] {
			case "is-enabled":
				return "disabled", 1, nil
			case "is-active":
				if active {
					return "active", 0, nil
				}
				return "inactive", 3, nil
			case "enable":
				active = true
			}
		}
		return "", 0, nil
	}
	second.runCmd = run
	adopted := false
	first.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		out, code, err := run(ctx, name, args...)
		if name == "systemd-tmpfiles" && err == nil && !adopted {
			adopted = true
			if _, err := runSteps(ctx, &second, io.Discard, []step{stepProvisionDisplay()}); err != nil {
				t.Fatalf("second installer failed: %v", err)
			}
			t.Log("second installer completed and adopted the first installer's rule")
		}
		return out, code, err
	}
	_, err := runSteps(t.Context(), first, io.Discard, []step{stepProvisionDisplay()})
	if err == nil || !adopted || !active {
		t.Fatalf("interleaving not reached: adopted=%v active=%v err=%v", adopted, active, err)
	}
	if _, err := os.Lstat(second.displayUnitPath); err != nil {
		t.Fatalf("successful second unit absent: %v", err)
	}
	_, ruleErr := os.Lstat(second.displayTmpfilesPath)
	t.Logf("first failed with %v; second remains active; rule error=%v", err, ruleErr)
	if errors.Is(ruleErr, os.ErrNotExist) {
		t.Fatal("failed first installer removed the boot rule adopted by the successful second installer")
	}
	if ruleErr != nil {
		t.Fatal(ruleErr)
	}
}

func TestDisplayRuntimeUndoPreservesRuleOnCleanupFailure(t *testing.T) {
	for _, scenario := range []string{"empty runtime", "nonempty runtime", "active display", "runtime removal denied", "runtime read denied", "runtime drift"} {
		t.Run(scenario, func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			st := stepProvisionDisplayRuntime()
			if changed, err := st.apply(t.Context(), env); err != nil || !changed {
				t.Fatalf("runtime setup: changed=%v err=%v", changed, err)
			}
			runtime := filepath.Dir(env.rfbSocketPath)
			want := ""
			switch scenario {
			case "nonempty runtime":
				if err := os.WriteFile(filepath.Join(runtime, "stale.socket"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				want = "preserve nonempty"
			case "active display":
				env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "active", 0, nil }
				want = "not confirmed stopped"
			case "runtime removal denied":
				remove := env.removeFile
				env.removeFile = func(path string) error {
					if path == runtime {
						return os.ErrPermission
					}
					return remove(path)
				}
				want = os.ErrPermission.Error()
			case "runtime read denied":
				env.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
				want = os.ErrPermission.Error()
			case "runtime drift":
				if err := os.Chmod(runtime, 0o750); err != nil { // #nosec G302 -- invalid 0750 runtime-directory drift must preserve the boot rule during failed cleanup.
					t.Fatal(err)
				}
				want = "want 0730"
			}
			err := st.undo(t.Context(), env)
			if want == "" {
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{runtime, env.displayTmpfilesPath} {
					if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("successful cleanup retained %s: %v", path, err)
					}
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("cleanup refusal not reported: %v, want %q", err, want)
			}
			if err := checkDisplayRuntimeRule(env.lstat, env.readFile, env.displayTmpfilesPath, env.rfbSocketPath); err != nil {
				t.Fatalf("failed cleanup lost the strict managed boot rule: %v", err)
			}
			t.Logf("cleanup refused with %v; strict managed rule retained", err)
		})
	}
}
