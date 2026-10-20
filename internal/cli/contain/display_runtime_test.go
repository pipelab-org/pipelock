// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func displayRuntimeTestEnv(t *testing.T) (*installEnv, *int) {
	t.Helper()
	env, _, _ := newFakeEnv(t)
	root := filepath.Dir(filepath.Dir(filepath.Dir(env.displayTmpfilesPath)))
	env.rfbSocketPath = filepath.Join(root, "run", "display", "rfb.sock")
	env.displayUnitPath = filepath.Join(root, "display.service")
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.configDir, "pipelock.yaml"), []byte("containment:\n  display:\n    enabled: true\n    backend: xvnc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "123", Gid: "456"}, nil }
	env.lstat = func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		mode := info.Mode()
		gid := uint32(0)
		if info.IsDir() {
			mode = os.ModeDir | 0o755
		}
		if path == filepath.Dir(env.rfbSocketPath) {
			mode = info.Mode()
			gid = 456
		}
		return viewerRuntimeInfo{viewerModeInfo{info, mode}, fakeFileSysWithOwner(0, gid)}, nil
	}
	calls := new(int)
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == "systemctl" && len(args) == 2 && args[0] == "is-active" {
			return "inactive", 3, nil
		}
		if name != "systemd-tmpfiles" || len(args) != 2 || args[0] != "--create" || args[1] != env.displayTmpfilesPath {
			t.Fatalf("unexpected command %s %q", name, args)
		}
		*calls++
		err := os.MkdirAll(filepath.Dir(env.rfbSocketPath), 0o730) //nolint:gosec // Match the managed root:viewer directory contract.
		if err == nil {
			err = os.Chmod(filepath.Dir(env.rfbSocketPath), 0o730) //nolint:gosec // Match the managed root:viewer directory contract.
		}
		return "", 0, err
	}
	return env, calls
}

func TestDisplayRuntimeLifecycle(t *testing.T) {
	env, calls := displayRuntimeTestEnv(t)
	ctx := context.Background()
	st := stepProvisionDisplayRuntime()
	changed, err := st.apply(ctx, env)
	if err != nil || !changed || *calls != 1 {
		t.Fatalf("install changed=%v calls=%d err=%v", changed, *calls, err)
	}
	body, err := os.ReadFile(env.displayTmpfilesPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(renderDisplayRuntimeRule(env.rfbSocketPath)) {
		t.Fatalf("rule = %q", body)
	}
	env.writeFile = func(string, []byte, os.FileMode) error {
		t.Fatal("repeated install rewrote unchanged rule")
		return nil
	}
	if changed, err := stepProvisionDisplayRuntime().apply(ctx, env); err != nil || changed || *calls != 2 {
		t.Fatalf("repeat changed=%v calls=%d err=%v", changed, *calls, err)
	}
	// A reboot removes /run. Applying the same persistent rule recreates it.
	if err := os.Remove(filepath.Dir(env.rfbSocketPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := stepProvisionDisplayRuntime().apply(ctx, env); err != nil {
		t.Fatal(err)
	}
	if err := st.undo(ctx, env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(env.displayTmpfilesPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback left rule: %v", err)
	}
}

func TestDisplayRuntimeRejectsUnsafeState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *installEnv)
	}{
		{"unmanaged", func(t *testing.T, e *installEnv) {
			if err := os.MkdirAll(filepath.Dir(e.displayTmpfilesPath), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(e.displayTmpfilesPath, []byte("# foreign\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, e *installEnv) {
			if err := os.MkdirAll(filepath.Dir(e.displayTmpfilesPath), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("absent", e.displayTmpfilesPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"runtime mode", func(t *testing.T, e *installEnv) {
			if err := os.MkdirAll(filepath.Dir(e.rfbSocketPath), 0o777); err != nil { //nolint:gosec // Unsafe directory fixture must be rejected.
				t.Fatal(err)
			}
		}},
		{"runtime symlink", func(t *testing.T, e *installEnv) {
			if err := os.MkdirAll(filepath.Dir(filepath.Dir(e.rfbSocketPath)), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), filepath.Dir(e.rfbSocketPath)); err != nil {
				t.Fatal(err)
			}
		}},
		{"rule owner", func(_ *testing.T, e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == e.displayTmpfilesPath {
					return fakeFileInfo{mode: 0o600, sys: fakeFileSysWithOwner(123, 0)}, nil
				}
				return old(p)
			}
		}},
		{"rule group", func(_ *testing.T, e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == e.displayTmpfilesPath {
					return fakeFileInfo{mode: 0o600, sys: fakeFileSysWithOwner(0, 456)}, nil
				}
				return old(p)
			}
		}},
		{"rule mode", func(_ *testing.T, e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == e.displayTmpfilesPath {
					return fakeFileInfo{mode: 0o644, sys: fakeFileSysWithOwner(0, 0)}, nil
				}
				return old(p)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, calls := displayRuntimeTestEnv(t)
			tc.mutate(t, env)
			if changed, err := stepProvisionDisplayRuntime().apply(context.Background(), env); err == nil || changed || *calls != 0 {
				t.Fatalf("unsafe state accepted: changed=%v calls=%d err=%v", changed, *calls, err)
			}
		})
	}
}

func TestDisplayRuntimeDisableAndRestore(t *testing.T) {
	for _, backend := range []string{"disabled", "xvfb"} {
		t.Run(backend, func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			ctx := context.Background()
			if _, err := stepProvisionDisplayRuntime().apply(ctx, env); err != nil {
				t.Fatal(err)
			}
			body := "containment:\n  display:\n    enabled: false\n"
			if backend == "xvfb" {
				body = "containment:\n  display:\n    enabled: true\n    backend: xvfb\n"
			}
			if err := os.WriteFile(filepath.Join(env.configDir, "pipelock.yaml"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			st := stepProvisionDisplayRuntime()
			if changed, err := st.apply(ctx, env); err != nil || !changed {
				t.Fatalf("disable %v %v", changed, err)
			}
			if err := st.undo(ctx, env); err != nil {
				t.Fatal(err)
			}
			if err := checkDisplayRuntimeRule(env.lstat, env.readFile, env.displayTmpfilesPath, env.rfbSocketPath); err != nil {
				t.Fatal(err)
			}
			if err := removeDisplayRuntimeRule(env); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDisplayRuntimeRuleDiagnostics(t *testing.T) {
	env, _ := displayRuntimeTestEnv(t)
	if err := checkDisplayRuntimeRule(env.lstat, env.readFile, env.displayTmpfilesPath, env.rfbSocketPath); err == nil || !strings.Contains(err.Error(), "rerun contain install") {
		t.Fatalf("missing diagnostic: %v", err)
	}
	if _, err := stepProvisionDisplayRuntime().apply(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.displayTmpfilesPath, []byte(displayUnitMarker+"\nd /run/wrong 0755 root root - -\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkDisplayRuntimeRule(env.lstat, env.readFile, env.displayTmpfilesPath, env.rfbSocketPath); err == nil {
		t.Fatal("drift accepted")
	}
}

// Existing transport fixtures supply sockets independently of the host's real
// /run; supply the matching boot contract without requiring root privileges.
func addDisplayRuntimeProbeFixture(t *testing.T, env *probeEnv) {
	t.Helper()
	env.displayTmpfilesPath = filepath.Join(t.TempDir(), "display.conf")
	oldStat, oldRead, oldLookup := env.lstat, env.readFile, env.lookupUser
	if oldStat == nil {
		oldStat = env.stat
	}
	env.lookupUser = func(name string) (*user.User, error) {
		u, err := oldLookup(name)
		if err != nil {
			return nil, err
		}
		if name == viewerUserName && u.Gid == "" {
			copyUser := *u
			copyUser.Gid = "0"
			return &copyUser, nil
		}
		return u, nil
	}
	env.readFile = func(path string) ([]byte, error) {
		if path == env.displayTmpfilesPath {
			return renderDisplayRuntimeRule(env.rfbSocketPath), nil
		}
		return oldRead(path)
	}
	viewer, err := env.lookupUser(viewerUserName)
	if err != nil {
		t.Fatal(err)
	}
	group, err := strconv.ParseUint(viewer.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	env.lstat = func(path string) (os.FileInfo, error) {
		if path == env.displayTmpfilesPath {
			return fakeFileInfo{mode: 0o600, sys: fakeFileSysWithOwner(0, 0)}, nil
		}
		if path == filepath.Dir(displayRFBPath(env.rfbSocketPath)) {
			return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(0, uint32(group))}, nil //nolint:gosec // ParseUint above enforces 32 bits.
		}
		return oldStat(path)
	}
}

func addDisplayRuntimeDoctorFixture(t *testing.T, env *doctorEnv) {
	t.Helper()
	probe := &probeEnv{rfbSocketPath: env.rfbSocketPath, lstat: env.lstat, stat: env.stat, readFile: env.readFile, lookupUser: env.lookupUser}
	addDisplayRuntimeProbeFixture(t, probe)
	env.displayTmpfilesPath, env.lstat, env.readFile, env.lookupUser = probe.displayTmpfilesPath, probe.lstat, probe.readFile, probe.lookupUser
}

func TestDisplayRuntimeFailedCreateRestoresPriorRule(t *testing.T) {
	for _, previous := range []string{"", displayUnitMarker + "\nd /run/previous 0730 root pipelock-viewer - -\n"} {
		t.Run(strconv.Itoa(len(previous)), func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			if previous != "" {
				if err := os.MkdirAll(filepath.Dir(env.displayTmpfilesPath), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(env.displayTmpfilesPath, []byte(previous), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "tmpfiles failed", 1, nil }
			if _, err := runSteps(context.Background(), env, io.Discard, []step{stepProvisionDisplayRuntime()}); err == nil {
				t.Fatal("failed tmpfiles accepted")
			}
			body, err := os.ReadFile(env.displayTmpfilesPath)
			if previous == "" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("new rule remains: %v", err)
				}
			} else if err != nil || string(body) != previous {
				t.Fatalf("prior rule not restored: %q %v", body, err)
			}
		})
	}
}

func TestDisplayRuntimeDoctorVerifyParity(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*probeEnv)
	}{
		{"valid", "", func(*probeEnv) {}},
		{"missing rule", "rerun contain install", func(e *probeEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == e.displayTmpfilesPath {
					return nil, os.ErrNotExist
				}
				return old(p)
			}
		}},
		{"rule owner", "root:root", func(e *probeEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == e.displayTmpfilesPath {
					return fakeFileInfo{mode: 0o600, sys: fakeFileSysWithOwner(12, 0)}, nil
				}
				return old(p)
			}
		}},
		{"rule group", "root:root", func(e *probeEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == e.displayTmpfilesPath {
					return fakeFileInfo{mode: 0o600, sys: fakeFileSysWithOwner(0, 12)}, nil
				}
				return old(p)
			}
		}},
		{"rule mode", "0600", func(e *probeEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == e.displayTmpfilesPath {
					return fakeFileInfo{mode: 0o644, sys: fakeFileSysWithOwner(0, 0)}, nil
				}
				return old(p)
			}
		}},
		{"rule contents", "rerun contain install", func(e *probeEnv) {
			old := e.readFile
			e.readFile = func(p string) ([]byte, error) {
				if p == e.displayTmpfilesPath {
					return []byte(displayUnitMarker + "\nd /run/wrong 0755 root root - -\n"), nil
				}
				return old(p)
			}
		}},
		{"missing runtime", "systemd-tmpfiles --create", func(e *probeEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.rfbSocketPath) || p == e.rfbSocketPath {
					return nil, os.ErrNotExist
				}
				return old(p)
			}
		}},
		{"runtime special mode", "want 0730", func(e *probeEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.rfbSocketPath) {
					return fakeFileInfo{mode: os.ModeDir | os.ModeSetgid | 0o730, sys: fakeFileSysWithOwner(0, 456)}, nil
				}
				return old(p)
			}
		}},
		{"runtime owner", "wrong owner or group", func(e *probeEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.rfbSocketPath) {
					return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(123, 456)}, nil
				}
				return old(p)
			}
		}},
		{"runtime mode", "want 0730", func(e *probeEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.rfbSocketPath) {
					return fakeFileInfo{mode: os.ModeDir | 0o750, sys: fakeFileSysWithOwner(0, 456)}, nil
				}
				return old(p)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			install, _ := displayRuntimeTestEnv(t)
			if _, err := stepProvisionDisplayRuntime().apply(context.Background(), install); err != nil {
				t.Fatal(err)
			}
			install.displayConfig = config.ContainmentDisplay{Backend: "xvnc"}
			unit := renderAgentDisplayUnit(install)
			if err := os.WriteFile(install.displayUnitPath, []byte(unit), 0o600); err != nil {
				t.Fatal(err)
			}
			probe := &probeEnv{configPath: managedPipelockConfigPath(install), displayUnitPath: install.displayUnitPath, displayTmpfilesPath: install.displayTmpfilesPath, rfbSocketPath: install.rfbSocketPath, agentUserName: install.agentUserName, lookupUser: install.lookupUser, readFile: install.readFile, lstat: func(p string) (os.FileInfo, error) {
				if p == install.rfbSocketPath {
					return fakeFileInfo{mode: os.ModeSocket | 0o600, sys: fakeFileSysWithOwner(123, 456)}, nil
				}
				return install.lstat(p)
			}}
			tc.change(probe)
			status, detail := probeAgentDisplayRFB(context.Background(), probe)
			doctor := &doctorEnv{configPath: probe.configPath, displayTmpfilesPath: probe.displayTmpfilesPath, rfbSocketPath: probe.rfbSocketPath, agentUserName: probe.agentUserName, lookupUser: probe.lookupUser, lstat: probe.lstat, readFile: probe.readFile, stat: func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o755}, nil }}
			result := checkDoctorDisplayRFB(context.Background(), doctor)
			if tc.want == "" {
				if status != statusPass || result.status != statusPass {
					t.Fatalf("valid verify=%s %s doctor=%+v", status, detail, result)
				}
			} else if status != statusFail || result.status != statusFail || !strings.Contains(detail, tc.want) || !strings.Contains(result.detail+result.remediation, tc.want) {
				t.Fatalf("verify=%s %s doctor=%+v want=%q", status, detail, result, tc.want)
			}
		})
	}
}

func TestDisplayRuntimeOperationalErrors(t *testing.T) {
	denied := errors.New("fixture denied")
	for _, tc := range []struct {
		name        string
		change      func(*installEnv)
		wantChanged bool
	}{
		{"rule stat", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == e.displayTmpfilesPath {
					return nil, denied
				}
				return old(p)
			}
		}, false},
		{"relative path", func(e *installEnv) { e.displayTmpfilesPath = "relative/display.conf" }, false},
		{"parent owner", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.displayTmpfilesPath) {
					return fakeFileInfo{mode: os.ModeDir | 0o750, sys: fakeFileSysWithOwner(12, 0)}, nil
				}
				return old(p)
			}
		}, false},
		{"parent writable", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.displayTmpfilesPath) {
					return fakeFileInfo{mode: os.ModeDir | 0o777, sys: fakeFileSysWithOwner(0, 0)}, nil
				}
				return old(p)
			}
		}, false},
		{"parent symlink", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.displayTmpfilesPath) {
					return fakeFileInfo{mode: os.ModeSymlink | 0o750, sys: fakeFileSysWithOwner(0, 0)}, nil
				}
				return old(p)
			}
		}, false},
		{"parent missing", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(filepath.Dir(e.displayTmpfilesPath)) {
					return nil, os.ErrNotExist
				}
				return old(p)
			}
		}, false},
		{"parent stat", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.displayTmpfilesPath) {
					return nil, denied
				}
				return old(p)
			}
		}, false},
		{"runtime owner", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.rfbSocketPath) {
					return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(12, 456)}, nil
				}
				return old(p)
			}
		}, false},
		{"runtime group", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.rfbSocketPath) {
					return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(0, 12)}, nil
				}
				return old(p)
			}
		}, false},
		{"runtime stat", func(e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.rfbSocketPath) {
					return nil, denied
				}
				return old(p)
			}
		}, false},
		{"mkdir", func(e *installEnv) { e.mkdirAll = func(string, os.FileMode) error { return denied } }, false},
		{"write", func(e *installEnv) { e.writeFile = func(string, []byte, os.FileMode) error { return denied } }, false},
		{"ownership", func(e *installEnv) { e.ownLeafNoFollow = func(string, os.FileMode, int, int) error { return denied } }, true},
		{"tmpfiles", func(e *installEnv) {
			e.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 1, denied }
		}, true},
		{"postcondition", func(e *installEnv) {
			e.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			tc.change(env)
			changed, err := stepProvisionDisplayRuntime().apply(context.Background(), env)
			if err == nil || changed != tc.wantChanged {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
		})
	}
}
