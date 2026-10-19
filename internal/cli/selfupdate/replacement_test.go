// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	originalBytes    = "original executable"
	replacementBytes = "verified replacement"
	changedBytes     = "concurrently changed"
)

// Simulate MoveFileW's no-clobber semantics; this is not Windows runtime proof.
func simulatedMove(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(src, dst)
}

func replacementFixture(t *testing.T) (target, candidate string) {
	t.Helper()
	dir := t.TempDir()
	target, candidate = filepath.Join(dir, "pipelock.exe"), filepath.Join(dir, "candidate.exe")
	writeReplacementFixture(t, target, originalBytes)
	writeReplacementFixture(t, candidate, replacementBytes)
	return target, candidate
}

func writeReplacementFixture(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertReplacementBytes(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil || string(got) != want {
		t.Fatalf("%s: got length=%d sha256=%s (%v), want length=%d sha256=%s", path, len(got), sum(got), err, len(want), sum([]byte(want)))
	}
}

func TestReplacementPhases(t *testing.T) {
	injected := errors.New("injected filesystem failure")
	tests := []struct {
		name   string
		setup  func(*testing.T, string, string, *replacementOps)
		want   string
		target string
		aside  string
	}{
		{name: "success", target: replacementBytes, aside: originalBytes},
		{name: "missing candidate", setup: func(t *testing.T, _, candidate string, _ *replacementOps) {
			if err := os.Remove(candidate); err != nil {
				t.Fatal(err)
			}
		}, want: "checking replacement; original unchanged", target: originalBytes},
		{name: "candidate is directory", setup: func(t *testing.T, _, candidate string, _ *replacementOps) {
			if err := os.Remove(candidate); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(candidate, 0o750); err != nil {
				t.Fatal(err)
			}
		}, want: "not a regular file", target: originalBytes},
		{name: "missing target", setup: func(t *testing.T, target, _ string, _ *replacementOps) {
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
		}, target: replacementBytes},
		{name: "missing target install fails", setup: func(t *testing.T, target, _ string, ops *replacementOps) {
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			ops.move = func(string, string) error { return injected }
		}, want: "installing at missing target"},
		{name: "original unreadable", setup: func(_ *testing.T, target, _ string, ops *replacementOps) {
			ops.digest = func(path string) (string, error) {
				if path == target {
					return "", os.ErrPermission
				}
				return binaryDigest(path)
			}
		}, want: "checking original", target: originalBytes},
		{name: "reserve denied", setup: func(_ *testing.T, _, _ string, ops *replacementOps) {
			ops.mkdir = func(string, os.FileMode) error { return os.ErrPermission }
		}, want: "reserving recovery directory", target: originalBytes},
		{name: "directory collision", setup: func(t *testing.T, target, _ string, _ *replacementOps) {
			if err := os.Mkdir(target+replacementSuffix, 0o750); err != nil {
				t.Fatal(err)
			}
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, "unrelated"), "keep")
		}, want: "remove that directory and retry", target: originalBytes},
		{name: "record collision", setup: func(t *testing.T, _, _ string, ops *replacementOps) {
			ops.write = func(path string, _ []byte, _ os.FileMode) error {
				writeReplacementFixture(t, path, "unrelated record")
				return os.ErrExist
			}
		}, want: "recording replacement", target: originalBytes},
		{name: "partial record write", setup: func(_ *testing.T, _, _ string, ops *replacementOps) {
			ops.write = func(path string, _ []byte, mode os.FileMode) error {
				if err := os.WriteFile(path, []byte("partial"), mode); err != nil {
					return err
				}
				return injected
			}
		}, want: "recording replacement", target: originalBytes},
		{name: "aside permission failure", setup: func(_ *testing.T, _, _ string, ops *replacementOps) {
			ops.move = func(string, string) error { return os.ErrPermission }
		}, want: "moving original aside (original unchanged)", target: originalBytes},
		{name: "aside collision", setup: func(t *testing.T, target, _ string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				if src == target {
					writeReplacementFixture(t, dst, "unrelated collision")
				}
				return simulatedMove(src, dst)
			}
		}, want: "moving original aside (original unchanged)", target: originalBytes, aside: "unrelated collision"},
		{name: "original changed before failed move", setup: func(t *testing.T, target, _ string, ops *replacementOps) {
			ops.move = func(string, string) error { writeReplacementFixture(t, target, changedBytes); return injected }
		}, want: "target changed", target: changedBytes},
		{name: "original removed before failed move", setup: func(t *testing.T, target, _ string, ops *replacementOps) {
			ops.move = func(string, string) error {
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				return injected
			}
		}, want: "target missing"},
		{name: "original state unknown", setup: func(_ *testing.T, target, _ string, ops *replacementOps) {
			failed := false
			ops.move = func(string, string) error { failed = true; return injected }
			ops.digest = func(path string) (string, error) {
				if failed && path == target {
					return "", os.ErrPermission
				}
				return binaryDigest(path)
			}
		}, want: "target state unknown", target: originalBytes},
		{name: "install fails restore succeeds", setup: func(_ *testing.T, _, candidate string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				if src == candidate {
					return injected
				}
				return simulatedMove(src, dst)
			}
		}, want: "original restored", target: originalBytes},
		{name: "restore denied", setup: func(_ *testing.T, target, candidate string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				if src == candidate || dst == target {
					return injected
				}
				return simulatedMove(src, dst)
			}
		}, want: "restore failed (target missing)", aside: originalBytes},
		{name: "concurrent target preserved", setup: func(t *testing.T, target, candidate string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				if src == candidate {
					writeReplacementFixture(t, target, changedBytes)
					return injected
				}
				return simulatedMove(src, dst)
			}
		}, want: "restore failed (target changed)", target: changedBytes, aside: originalBytes},
		{name: "concurrent identical target preserved", setup: func(t *testing.T, target, candidate string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				if src == candidate {
					writeReplacementFixture(t, target, originalBytes)
					return injected
				}
				return simulatedMove(src, dst)
			}
		}, want: "restore failed (original unchanged)", target: originalBytes, aside: originalBytes},
		{name: "saved image changed", setup: func(t *testing.T, target, _ string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				err := simulatedMove(src, dst)
				if err == nil && src == target {
					writeReplacementFixture(t, dst, changedBytes)
				}
				return err
			}
		}, want: "saved image restored (target changed)", target: changedBytes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, candidate := replacementFixture(t)
			writeReplacementFixture(t, target+backupSuffix, "existing rollback backup")
			ops := replacementOps{move: simulatedMove}
			if tt.setup != nil {
				tt.setup(t, target, candidate, &ops)
			}
			err := replaceRunningBinary(candidate, target, ops)
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("error=%v, want %q", err, tt.want)
			}
			if tt.target != "" {
				assertReplacementBytes(t, target, tt.target)
			} else if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("target should remain missing: %v", err)
			}
			if tt.aside != "" {
				assertReplacementBytes(t, filepath.Join(target+replacementSuffix, priorImageName), tt.aside)
			}
			assertReplacementBytes(t, target+backupSuffix, "existing rollback backup")
		})
	}
}

func TestReplacementCleanup(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*testing.T, string)
		failRemove string
		want       string
	}{
		{name: "completed replacement"},
		{name: "original restored from backup", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, target, originalBytes)
		}},
		{name: "nothing pending", mutate: func(t *testing.T, target string) {
			if err := cleanupReplacement(target, replacementOps{}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "prior already removed", mutate: func(t *testing.T, target string) {
			if err := os.Remove(filepath.Join(target+replacementSuffix, priorImageName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "partial restore cleanup", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, target, originalBytes)
			if err := os.Remove(filepath.Join(target+replacementSuffix, priorImageName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "empty directory after interrupted cleanup", mutate: func(t *testing.T, target string) {
			for _, name := range []string{priorImageName, replacementRecordName} {
				if err := os.Remove(filepath.Join(target+replacementSuffix, name)); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "changed prior", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, priorImageName), changedBytes)
		}, want: "images differ"},
		{name: "changed installed", mutate: func(t *testing.T, target string) { writeReplacementFixture(t, target, changedBytes) }, want: "images differ"},
		{name: "extra entry", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, "unrelated"), "keep")
		}, want: "unrecognized recovery entry"},
		{name: "missing record", mutate: func(t *testing.T, target string) {
			if err := os.Remove(filepath.Join(target+replacementSuffix, replacementRecordName)); err != nil {
				t.Fatal(err)
			}
		}, want: "checking recovery record"},
		{name: "short record", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, replacementRecordName), "x")
		}, want: "unrecognized recovery record"},
		{name: "bad newlines", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, replacementRecordName), strings.Repeat("a", 2*(sha256HexLength+1)))
		}, want: "invalid recovery record"},
		{name: "bad hex", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, replacementRecordName), strings.Repeat("z", sha256HexLength)+"\n"+strings.Repeat("a", sha256HexLength)+"\n")
		}, want: "invalid recovery digests"},
		{name: "target missing", mutate: func(t *testing.T, target string) {
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
		}, want: "checking installed image"},
		{name: "prior directory", mutate: func(t *testing.T, target string) {
			p := filepath.Join(target+replacementSuffix, priorImageName)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o750); err != nil {
				t.Fatal(err)
			}
		}, want: "checking prior image"},
		{name: "changed target after prior removed", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, target, changedBytes)
			if err := os.Remove(filepath.Join(target+replacementSuffix, priorImageName)); err != nil {
				t.Fatal(err)
			}
		}, want: "installed image differs"},
		{name: "mapped prior", failRemove: priorImageName, want: "removing prior image"},
		{name: "record removal denied", failRemove: replacementRecordName, want: "removing recovery record"},
		{name: "directory removal denied", failRemove: "directory", want: "removing recovery directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, candidate := replacementFixture(t)
			writeReplacementFixture(t, target+backupSuffix, "rollback")
			if err := replaceRunningBinary(candidate, target, replacementOps{move: simulatedMove}); err != nil {
				t.Fatal(err)
			}
			if tt.mutate != nil {
				tt.mutate(t, target)
			}
			ops := replacementOps{remove: func(path string) error {
				if filepath.Base(path) == tt.failRemove || tt.failRemove == "directory" && path == target+replacementSuffix {
					return os.ErrPermission
				}
				return os.Remove(path)
			}}
			err := cleanupReplacement(target, ops)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(target + replacementSuffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovery directory remains: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v want %q", err, tt.want)
			}
			assertReplacementBytes(t, target+backupSuffix, "rollback")
			if tt.failRemove != "" {
				if err := cleanupReplacement(target, replacementOps{}); err != nil {
					t.Fatalf("retry cleanup: %v", err)
				}
			}
		})
	}
}

// SHA256 hex representation length, shared by malformed-record cases.
const sha256HexLength = sha256.Size * 2

func TestReplacementRejectsUnownedPaths(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "record symlink", "prior symlink"} {
		t.Run(kind, func(t *testing.T) {
			target, candidate := replacementFixture(t)
			dir := target + replacementSuffix
			unrelated := filepath.Join(t.TempDir(), "unrelated")
			writeReplacementFixture(t, unrelated, originalBytes)
			switch kind {
			case "file":
				writeReplacementFixture(t, dir, "keep")
			case "symlink":
				if err := os.Symlink(filepath.Dir(unrelated), dir); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			default:
				if err := replaceRunningBinary(candidate, target, replacementOps{move: simulatedMove}); err != nil {
					t.Fatal(err)
				}
				name := replacementRecordName
				if kind == "prior symlink" {
					name = priorImageName
				}
				path := filepath.Join(dir, name)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(unrelated, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			if err := cleanupReplacement(target, replacementOps{}); err == nil {
				t.Fatal("accepted unowned path")
			}
			assertReplacementBytes(t, unrelated, originalBytes)
		})
	}
}

func TestReplacementRestoreCleanupFailure(t *testing.T) {
	target, candidate := replacementFixture(t)
	err := replaceRunningBinary(candidate, target, replacementOps{move: func(src, dst string) error {
		if src == candidate {
			return fmt.Errorf("injected install failure")
		}
		return simulatedMove(src, dst)
	}, remove: func(string) error { return os.ErrPermission }})
	if err == nil || !strings.Contains(err.Error(), "original restored") {
		t.Fatalf("error=%v", err)
	}
	assertReplacementBytes(t, target, originalBytes)
	if err := cleanupReplacement(target, replacementOps{}); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementDigestBoundsAndPermissions(t *testing.T) {
	for _, kind := range []string{"oversized", "unreadable", "directory"} {
		t.Run(kind, func(t *testing.T) {
			target, _ := replacementFixture(t)
			var want error
			switch kind {
			case "oversized":
				if err := os.Truncate(target, maxDownloadBytes+1); err != nil {
					t.Fatal(err)
				}
				want = ErrBinaryTooLarge
			case "unreadable":
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("permission checks unavailable as root")
				}
				if err := os.Chmod(target, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(target, 0o600) })
				want = os.ErrPermission
			case "directory":
				target = filepath.Dir(target)
			}
			_, err := binaryDigest(target)
			if err == nil {
				t.Fatal("accepted invalid binary")
			}
			if want != nil && !errors.Is(err, want) {
				t.Fatalf("error=%v, want %v", err, want)
			}
		})
	}
}

// A later install by another tool leaves recovery state cleanup cannot prove it
// owns. It is retained, and the next update tells the operator how to proceed
// without touching the installed image or the rollback backup.
func TestReplacementRetainedRecoveryBlocksUpdate(t *testing.T) {
	target, candidate := replacementFixture(t)
	writeReplacementFixture(t, target+backupSuffix, "rollback")
	if err := replaceRunningBinary(candidate, target, replacementOps{move: simulatedMove}); err != nil {
		t.Fatal(err)
	}
	writeReplacementFixture(t, target, changedBytes)
	if err := cleanupReplacement(target, replacementOps{}); err == nil || !strings.Contains(err.Error(), "images differ") {
		t.Fatalf("cleanup error=%v, want images differ", err)
	}
	next := filepath.Join(filepath.Dir(target), "next.exe")
	writeReplacementFixture(t, next, "next update")
	err := replaceRunningBinary(next, target, replacementOps{move: simulatedMove})
	if err == nil || !strings.Contains(err.Error(), "remove that directory and retry") || !errors.Is(err, os.ErrExist) {
		t.Fatalf("update error=%v, want operator remedy wrapping ErrExist", err)
	}
	if !strings.Contains(err.Error(), "stop processes still running the previous executable") {
		t.Fatalf("update error=%v, want mapped-image remedy before directory removal", err)
	}
	assertReplacementBytes(t, target, changedBytes)
	assertReplacementBytes(t, target+backupSuffix, "rollback")
	assertReplacementBytes(t, filepath.Join(target+replacementSuffix, priorImageName), originalBytes)
}

func TestReplacementRetainedRollback(t *testing.T) {
	injected := errors.New("injected rollback failure")
	for _, tt := range []struct {
		name   string
		mutate func(*testing.T, string, string, *replacementOps)
		want   string
		target string
	}{
		{name: "success", target: originalBytes},
		{name: "backup changed", mutate: func(t *testing.T, _, candidate string, _ *replacementOps) {
			writeReplacementFixture(t, candidate, changedBytes)
		}, want: "backup differs", target: replacementBytes},
		{name: "candidate missing", mutate: func(t *testing.T, _, candidate string, _ *replacementOps) {
			if err := os.Remove(candidate); err != nil {
				t.Fatal(err)
			}
		}, want: "backup differs", target: replacementBytes},
		{name: "prior changed", mutate: func(t *testing.T, target, _ string, _ *replacementOps) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, priorImageName), changedBytes)
		}, want: "images differ", target: replacementBytes},
		{name: "target changed", mutate: func(t *testing.T, target, _ string, _ *replacementOps) {
			writeReplacementFixture(t, target, changedBytes)
		}, want: "images differ", target: changedBytes},
		{name: "record changed", mutate: func(t *testing.T, target, _ string, _ *replacementOps) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, replacementRecordName), "bad")
		}, want: "unrecognized recovery record", target: replacementBytes},
		{name: "extra entry", mutate: func(t *testing.T, target, _ string, _ *replacementOps) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, "unrelated"), "keep")
		}, want: "unrecognized recovery entry", target: replacementBytes},
		{name: "incomplete cleanup", mutate: func(t *testing.T, target, _ string, _ *replacementOps) {
			if err := os.Remove(filepath.Join(target+replacementSuffix, priorImageName)); err != nil {
				t.Fatal(err)
			}
		}, want: "incomplete recovery state", target: replacementBytes},
		{name: "rollback slot collision", mutate: func(t *testing.T, target, _ string, _ *replacementOps) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, rollbackImageName), changedBytes)
		}, want: "images differ", target: replacementBytes},
		{name: "rollback slot directory", mutate: func(t *testing.T, target, _ string, _ *replacementOps) {
			if err := os.Mkdir(filepath.Join(target+replacementSuffix, rollbackImageName), 0o750); err != nil {
				t.Fatal(err)
			}
		}, want: "checking replaced image", target: replacementBytes},
		{name: "first move fails", mutate: func(_ *testing.T, _, _ string, ops *replacementOps) {
			ops.move = func(string, string) error { return injected }
		}, want: "original unchanged", target: replacementBytes},
		{name: "second move fails", mutate: func(_ *testing.T, _, candidate string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				if src == candidate {
					return injected
				}
				return simulatedMove(src, dst)
			}
		}, want: "original restored", target: replacementBytes},
		{name: "restore fails", mutate: func(_ *testing.T, target, _ string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				if src != target {
					return injected
				}
				return simulatedMove(src, dst)
			}
		}, want: "restore failed (target missing)"},
		{name: "restore collision", mutate: func(_ *testing.T, target, candidate string, ops *replacementOps) {
			ops.move = func(src, dst string) error {
				if src == candidate {
					writeReplacementFixture(t, target, changedBytes)
					return injected
				}
				return simulatedMove(src, dst)
			}
		}, want: "restore failed (target changed)", target: changedBytes},
		{name: "saved image changed", mutate: func(_ *testing.T, target, _ string, ops *replacementOps) {
			ops.digest = func(path string) (string, error) {
				if path == filepath.Join(target+replacementSuffix, rollbackImageName) {
					if _, err := os.Stat(path); err == nil {
						return "", injected
					}
				}
				return binaryDigest(path)
			}
		}, want: "original restored", target: replacementBytes},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target, candidate := replacementFixture(t)
			writeReplacementFixture(t, target+backupSuffix, originalBytes)
			if err := replaceRunningBinary(candidate, target, replacementOps{move: simulatedMove}); err != nil {
				t.Fatal(err)
			}
			writeReplacementFixture(t, candidate, originalBytes)
			ops := replacementOps{move: simulatedMove}
			if tt.mutate != nil {
				tt.mutate(t, target, candidate, &ops)
			}
			err := rollbackRetained(candidate, target, ops)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				assertReplacementBytes(t, filepath.Join(target+replacementSuffix, priorImageName), originalBytes)
				assertReplacementBytes(t, filepath.Join(target+replacementSuffix, rollbackImageName), replacementBytes)
				// A second rollback is idempotent and never adds another generation.
				writeReplacementFixture(t, candidate, originalBytes)
				if err := rollbackRetained(candidate, target, ops); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{priorImageName, rollbackImageName} {
					err := cleanupRecovery(target, replacementOps{remove: func(path string) error {
						if filepath.Base(path) == name {
							return injected
						}
						return os.Remove(path)
					}})
					if !errors.Is(err, injected) {
						t.Fatalf("mapped %s cleanup: %v", name, err)
					}
				}
				if err := cleanupRecovery(target, replacementOps{}); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("rollback = %v, want %q", err, tt.want)
			}
			if tt.target != "" {
				assertReplacementBytes(t, target, tt.target)
			} else if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing target = %v", err)
			}
			assertReplacementBytes(t, target+backupSuffix, originalBytes)
		})
	}
}

func TestReplacementRollbackWithoutRecovery(t *testing.T) {
	target, candidate := replacementFixture(t)
	if err := rollbackRetained(candidate, target, replacementOps{move: simulatedMove}); err != nil {
		t.Fatal(err)
	}
	assertReplacementBytes(t, target, replacementBytes)
}

func TestReplacementRollbackAfterManualRestore(t *testing.T) {
	target, candidate := replacementFixture(t)
	if err := replaceRunningBinary(candidate, target, replacementOps{move: simulatedMove}); err != nil {
		t.Fatal(err)
	}
	writeReplacementFixture(t, target, originalBytes)
	writeReplacementFixture(t, candidate, originalBytes)
	if err := rollbackRetained(candidate, target, replacementOps{move: func(string, string) error { t.Fatal("already restored image must not move"); return nil }}); err != nil {
		t.Fatal(err)
	}
	assertReplacementBytes(t, target, originalBytes)
	assertReplacementBytes(t, filepath.Join(target+replacementSuffix, priorImageName), originalBytes)
	if err := cleanupRecovery(target, replacementOps{}); err != nil {
		t.Fatal(err)
	}
}
