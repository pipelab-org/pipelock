// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisplayRuntimeCleanup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		change    func(*testing.T, *installEnv)
		wantError bool
	}{
		{"empty", func(*testing.T, *installEnv) {}, false},
		{"active", func(_ *testing.T, e *installEnv) {
			e.runCmd = func(context.Context, string, ...string) (string, int, error) { return "active", 0, nil }
		}, true},
		{"unknown", func(_ *testing.T, e *installEnv) {
			e.runCmd = func(context.Context, string, ...string) (string, int, error) { return "unknown", 4, nil }
		}, true},
		{"systemctl error", func(_ *testing.T, e *installEnv) {
			e.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 1, os.ErrPermission }
		}, true},
		{"nonempty", func(t *testing.T, e *installEnv) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(e.rfbSocketPath), "preserve"), []byte("operator data"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"type", func(t *testing.T, e *installEnv) {
			runtime := filepath.Dir(e.rfbSocketPath)
			if err := os.Remove(runtime); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(runtime, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"symlink", func(t *testing.T, e *installEnv) {
			runtime := filepath.Dir(e.rfbSocketPath)
			if err := os.Remove(runtime); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), runtime); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"mode", func(t *testing.T, e *installEnv) {
			if err := os.Chmod(filepath.Dir(e.rfbSocketPath), 0o700); err != nil { //nolint:gosec // Directory permission drift fixture.
				t.Fatal(err)
			}
		}, true},
		{"owner", func(_ *testing.T, e *installEnv) {
			old := e.lstat
			e.lstat = func(p string) (os.FileInfo, error) {
				if p == filepath.Dir(e.rfbSocketPath) {
					return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(123, 456)}, nil
				}
				return old(p)
			}
		}, true},
		{"read error", func(_ *testing.T, e *installEnv) {
			e.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
		}, true},
		{"remove error", func(_ *testing.T, e *installEnv) { e.removeFile = func(string) error { return os.ErrPermission } }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			if _, err := stepProvisionDisplayRuntime().apply(context.Background(), env); err != nil {
				t.Fatal(err)
			}
			tc.change(t, env)
			err := removeEmptyDisplayRuntime(context.Background(), env)
			if (err != nil) != tc.wantError {
				t.Fatalf("cleanup err=%v wantError=%v", err, tc.wantError)
			}
			_, statErr := os.Lstat(filepath.Dir(env.rfbSocketPath))
			if tc.wantError && statErr != nil {
				t.Fatalf("unsafe path removed: %v", statErr)
			}
			if !tc.wantError && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("empty directory retained: %v", statErr)
			}
			if tc.name == "nonempty" {
				body, err := os.ReadFile(filepath.Join(filepath.Dir(env.rfbSocketPath), "preserve"))
				if err != nil || string(body) != "operator data" {
					t.Fatalf("contents changed: %q %v", body, err)
				}
			}
		})
	}
}

func TestDisplayRuntimeViewerAccountRemoval(t *testing.T) {
	for _, undoInstall := range []bool{false, true} {
		for _, unsafe := range []string{"", "nonempty", "active", "mode"} {
			t.Run(fmt.Sprintf("undo=%v/%s", undoInstall, unsafe), func(t *testing.T) {
				env, _ := displayRuntimeTestEnv(t)
				ctx := context.Background()
				if _, err := stepProvisionDisplayRuntime().apply(ctx, env); err != nil {
					t.Fatal(err)
				}
				// Disabling display removes its rule but leaves the runtime directory.
				if err := removeDisplayRuntimeRule(env); err != nil {
					t.Fatal(err)
				}
				marker := viewerCreationMarkerPath(env)
				if err := os.MkdirAll(filepath.Dir(marker), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, []byte("123\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				runtime := filepath.Dir(env.rfbSocketPath)
				switch unsafe {
				case "nonempty":
					if err := os.WriteFile(filepath.Join(runtime, "preserve"), []byte("data"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "mode":
					if err := os.Chmod(runtime, 0o700); err != nil { //nolint:gosec // Directory permission drift fixture.
						t.Fatal(err)
					}
				}
				oldRun := env.runCmd
				deleted := false
				env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
					if name == "userdel" {
						if _, err := os.Lstat(runtime); !errors.Is(err, os.ErrNotExist) {
							t.Fatal("account deleted before runtime directory")
						}
						deleted = true
						return "", 0, nil
					}
					if unsafe == "active" && name == "systemctl" {
						return "active", 0, nil
					}
					return oldRun(ctx, name, args...)
				}
				st := actionMaybeDeleteViewerUser(rollbackOpts{purgeUsers: true})
				if undoInstall {
					st = stepCreateViewerUser()
				}
				err := st.undo(ctx, env)
				if unsafe != "" {
					if err == nil || deleted || !strings.Contains(err.Error(), "preserving viewer account") {
						t.Fatalf("unsafe cleanup err=%v deleted=%v", err, deleted)
					}
					if _, err := os.Stat(marker); err != nil {
						t.Fatalf("creation record lost: %v", err)
					}
					if _, err := os.Lstat(runtime); err != nil {
						t.Fatalf("runtime lost: %v", err)
					}
					return
				}
				if err != nil || !deleted {
					t.Fatalf("cleanup err=%v deleted=%v", err, deleted)
				}
				if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("creation record retained: %v", err)
				}
				// A recreated identity can provision a fresh runtime with its own group.
				if _, err := stepProvisionDisplayRuntime().apply(ctx, env); err != nil {
					t.Fatalf("reinstall: %v", err)
				}
			})
		}
	}
}
