// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	releasetrust "github.com/luckyPipewrench/pipelock/internal/release"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const windowsHelperMode = "PIPELOCK_TEST_SELFUPDATE_MODE"

// TestWindowsRunningExecutableReplacement executes a copied test executable,
// not a simulated filesystem target. The child runs the updater's CLI handler
// against a locally signed release; rollback uses the public command and flags.
// CI test-windows runs every TestWindows case in this package.
func TestWindowsRunningExecutableReplacement(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "pipelock.exe")
	if err := copyFile(exe, target); err != nil {
		t.Fatal(err)
	}
	target, err = filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	original := windowsFileIdentity(t, target)
	binary, err := os.ReadFile(filepath.Clean(exe))
	if err != nil {
		t.Fatal(err)
	}
	archiveName := assetName(versionTag(testLatest), "windows", testGOARCH)
	archive := makeZip(t, map[string][]byte{"pipelock.exe": binary})
	checksums := []byte(fmt.Sprintf("%s  %s\n", sum(archive), archiveName))
	manifest, signature := signedReleaseManifest(t, testLatest, "windows", archiveName, archive, checksums)
	rs := newReleaseServer(t, testLatest, map[string][]byte{archiveName: archive, checksumsFile: checksums, releasetrust.ManifestFile: manifest, releasetrust.ManifestSigFile: signature})
	run := func(mode string) []byte {
		t.Helper()
		child := exec.CommandContext(context.Background(), target, "-test.run=^TestWindowsReplacementChild$") // #nosec G204 -- copied test executable in TempDir
		child.Env = append(os.Environ(), windowsHelperMode+"="+mode, "PIPELOCK_TEST_UPDATE_API="+rs.srv.URL)
		out, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("child %s: %v\n%s", mode, err, out)
		}
		return out
	}
	assertApplied := func(out []byte) {
		t.Helper()
		// The Go test runner adds PASS after the CLI's JSON object.
		var st Status
		if err := json.NewDecoder(bytes.NewReader(out)).Decode(&st); err != nil {
			t.Fatalf("CLI JSON: %v\n%s", err, out)
		}
		if !st.Applied || st.TargetPath != target || st.BackupPath != target+backupSuffix {
			t.Fatalf("CLI status=%+v", st)
		}
	}
	assertApplied(run("update"))
	installed := windowsFileIdentity(t, target)
	if os.SameFile(original, installed) {
		t.Fatal("update retained the original file identity")
	}
	assertReplacementBytes(t, target, string(binary))
	assertReplacementBytes(t, target+backupSuffix, string(binary))
	assertReplacementBytes(t, filepath.Join(target+replacementSuffix, priorImageName), string(binary))
	// First subsequent startup removes the now-unmapped prior image only.
	run("startup")
	if _, err := os.Lstat(target + replacementSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("startup left recovery files: %v", err)
	}
	assertReplacementBytes(t, target+backupSuffix, string(binary))
	assertApplied(run("rollback"))
	restored := windowsFileIdentity(t, target)
	if os.SameFile(installed, restored) {
		t.Fatal("rollback retained the installed file identity")
	}
	run("startup")
	if _, err := os.Lstat(target + replacementSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback startup left recovery files: %v", err)
	}
	assertReplacementBytes(t, target+backupSuffix, string(binary))
}

func TestWindowsReplacementChild(t *testing.T) {
	mode := os.Getenv(windowsHelperMode)
	if mode == "" {
		return
	}
	if mode == "hold image" {
		_, _ = fmt.Fprintln(os.Stdout, "ready")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	if mode == "lock probe" {
		unlock, err := acquireReplacementLock(os.Getenv("PIPELOCK_TEST_LOCK_TARGET"))
		if os.Getenv("PIPELOCK_TEST_LOCK_BUSY") == "true" {
			if !errors.Is(err, errReplacementBusy) {
				if unlock != nil {
					unlock()
				}
				t.Fatalf("lock contention = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		unlock()
		return
	}
	var warnings bytes.Buffer
	CleanupOnStart(&warnings)
	if warnings.Len() != 0 {
		t.Fatal(warnings.String())
	}
	switch mode {
	case "startup":
		return
	case "update":
		// Prove the child really is replacing its own mapped image: the historical
		// delete-first algorithm must fail here before running the repaired path.
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(exe); err == nil {
			t.Fatal("running image was deletable; regression premise not exercised")
		}
		cmd := Cmd()
		opts := &Options{APIBase: os.Getenv("PIPELOCK_TEST_UPDATE_API"), CurrentVersion: testCurrent, GOOS: "windows", GOARCH: testGOARCH, ReleaseKeyringHex: testReleasePubHex, CosignAvailable: func() bool { return false }, JSON: true}
		if err := runCommand(context.Background(), cmd, opts, false); err != nil {
			t.Fatal(err)
		}
		if err := cleanupReplacement(opts.TargetPath, replacementOps{}); err == nil {
			t.Fatal("cleanup removed the still-mapped prior image")
		}
	case "rollback":
		cmd := Cmd()
		cmd.SetArgs([]string{"--rollback", "--json"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown child mode %q", mode)
	}
}

func TestWindowsReplacementLock(t *testing.T) {
	target, _ := replacementFixture(t)
	unlock, err := acquireReplacementLock(target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { unlock() }()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := func(busy string) {
		t.Helper()
		child := exec.CommandContext(t.Context(), exe, "-test.run=^TestWindowsReplacementChild$") // #nosec G204 -- current test executable
		child.Env = append(os.Environ(), windowsHelperMode+"=lock probe", "PIPELOCK_TEST_LOCK_TARGET="+target, "PIPELOCK_TEST_LOCK_BUSY="+busy)
		if out, err := child.CombinedOutput(); err != nil {
			t.Fatalf("cross-process lock probe: %v\n%s", err, out)
		}
	}
	probe("true")
	lockPath := target + replacementSuffix + ".lock"
	if err := os.Remove(lockPath); err == nil {
		t.Fatal("held lock could be deleted")
	}
	unlock()
	unlock = func() {}
	probe("false")
}

func TestWindowsReplacementLockInvalidPaths(t *testing.T) {
	for _, kind := range []string{"invalid name", "missing parent", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			target, _ := replacementFixture(t)
			lockPath := target + replacementSuffix + ".lock"
			switch kind {
			case "invalid name":
				target += "\x00"
			case "missing parent":
				target = filepath.Join(target, "missing", "pipelock.exe")
			case "directory":
				if err := os.Mkdir(lockPath, 0o750); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(target, lockPath); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			unlock, err := acquireReplacementLock(target)
			if unlock != nil {
				unlock()
			}
			if err == nil {
				t.Fatal("accepted invalid lock path")
			}
		})
	}
}

func TestWindowsReplacementCleanupExcludesLaterUpdate(t *testing.T) {
	target, candidate := replacementFixture(t)
	if _, err := installBinary(target, candidate); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(filepath.Dir(target), "next.exe")
	writeReplacementFixture(t, next, changedBytes)
	aside := filepath.Join(target+replacementSuffix, priorImageName)
	checked := false
	err := cleanupReplacement(target, replacementOps{digest: func(path string) (string, error) {
		digest, err := binaryDigest(path)
		if path == aside {
			checked = true
			if _, err := installBinary(target, next); !errors.Is(err, errReplacementBusy) {
				t.Fatalf("update while cleanup owns recovery = %v", err)
			}
			if _, err := rollback(target); !errors.Is(err, errReplacementBusy) {
				t.Fatalf("rollback while cleanup owns recovery = %v", err)
			}
			assertReplacementBytes(t, target+backupSuffix, originalBytes)
		}
		return digest, err
	}})
	if err != nil || !checked {
		t.Fatalf("cleanup = %v, checked contention = %v", err, checked)
	}
	if _, err := installBinary(target, next); err != nil {
		t.Fatal(err)
	}
	assertReplacementBytes(t, aside, replacementBytes)
	assertReplacementBytes(t, target, changedBytes)
	assertReplacementBytes(t, target+backupSuffix, replacementBytes)
}

func TestWindowsMoveWithoutReplace(t *testing.T) {
	for _, tt := range []struct{ name, src, dst string }{
		{name: "invalid source", src: "bad\x00source", dst: "unused"},
		{name: "invalid destination", src: "unused", dst: "bad\x00destination"},
		{name: "collision"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "collision" {
				src, dst := replacementFixture(t)
				if err := moveWithoutReplace(src, dst); !errors.Is(err, os.ErrExist) {
					t.Fatalf("collision: %v", err)
				}
				assertReplacementBytes(t, src, originalBytes)
				assertReplacementBytes(t, dst, replacementBytes)
			} else if err := moveWithoutReplace(tt.src, tt.dst); err == nil {
				t.Fatal("accepted invalid path")
			}
		})
	}
}

func TestWindowsReplacementSharingViolation(t *testing.T) {
	target, candidate := replacementFixture(t)
	path, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	// Allow backup/hash reads, but deny the delete access required by rename.
	handle, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Error(err)
		}
	}()
	_, err = installBinary(target, candidate)
	if err == nil || !strings.Contains(err.Error(), "original unchanged") || strings.Contains(err.Error(), "restore failed") {
		t.Fatalf("sharing violation: %v", err)
	}
	assertReplacementBytes(t, target, originalBytes)
	assertReplacementBytes(t, target+backupSuffix, originalBytes)
	assertReplacementBytes(t, candidate, replacementBytes)
}

// File.Stat captures the Windows file ID immediately. os.Stat defers that ID
// lookup until SameFile, which would inspect the replacement at the old path.
func windowsFileIdentity(t *testing.T, path string) os.FileInfo {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test-owned executable
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	closeErr := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return info
}

// Keep both generations mapped across the operation, as a running service and
// an updater launched from its replacement would do.
func TestWindowsRetainedRecoveryRollback(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "pipelock.exe")
	candidate := filepath.Join(dir, "candidate.exe")
	if err := copyFile(exe, target); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(exe, candidate); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Clean(candidate), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteString("replacement PE overlay")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(errors.Join(writeErr, closeErr))
	}
	original, err := binaryDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	hold := func() func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(30*time.Second))
		child := exec.CommandContext(ctx, target, "-test.run=^TestWindowsReplacementChild$") // #nosec G204 -- test-owned executable
		child.Env = append(os.Environ(), windowsHelperMode+"=hold image")
		input, err := child.StdinPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		output, err := child.StdoutPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = input.Close()
			if err := child.Wait(); err != nil {
				t.Error(err)
			}
			cancel()
		}
		t.Cleanup(stop)
		ready, err := bufio.NewReader(output).ReadString('\n')
		if err != nil || strings.TrimSpace(ready) != "ready" {
			t.Fatalf("holder readiness: %q %v", ready, err)
		}
		return stop
	}
	stopOriginal := hold()
	if _, err := installBinary(target, candidate); err != nil {
		t.Fatal(err)
	}
	prior := filepath.Join(target+replacementSuffix, priorImageName)
	if err := os.Remove(prior); err == nil {
		t.Fatal("original image was not mapped")
	}
	stopInstalled := hold()
	if !t.Run("refused update preserves backup", func(t *testing.T) {
		if err := copyFile(exe, candidate); err != nil {
			t.Fatal(err)
		}
		if _, err := installBinary(target, candidate); err == nil {
			t.Fatal("second update accepted retained recovery")
		}
		got, err := binaryDigest(target + backupSuffix)
		if err != nil || got != original {
			t.Fatalf("refused update changed rollback backup: digest=%s want=%s err=%v", got, original, err)
		}
	}) {
		return
	}
	if !t.Run("immediate rollback", func(t *testing.T) {
		if _, err := rollback(target); err != nil {
			t.Fatal(err)
		}
		got, err := binaryDigest(target)
		if err != nil || got != original {
			t.Fatalf("rollback digest=%s want=%s err=%v", got, original, err)
		}
	}) {
		return
	}

	displaced := filepath.Join(target+replacementSuffix, rollbackImageName)
	for _, path := range []string{prior, displaced} {
		if err := os.Remove(path); err == nil {
			t.Fatalf("mapped image deleted: %s", path)
		}
	}
	identity := windowsFileIdentity(t, displaced)
	if _, err := rollback(target); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(identity, windowsFileIdentity(t, displaced)) {
		t.Fatal("repeated rollback changed saved image")
	}
	stopOriginal()
	if err := cleanupReplacement(target, replacementOps{}); err == nil {
		t.Fatal("cleanup removed mapped updated image")
	}
	if _, err := os.Lstat(prior); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original image not cleaned: %v", err)
	}
	if _, err := rollback(target); err != nil {
		t.Fatal(err)
	}
	stopInstalled()
	if err := cleanupReplacement(target, replacementOps{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target + replacementSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained recovery after cleanup: %v", err)
	}
}

func TestWindowsRetainedRecoveryRefusals(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "valid retained state"},
		{name: "malformed record", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, replacementRecordName), "bad")
		}},
		{name: "changed prior", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, priorImageName), changedBytes)
		}},
		{name: "changed target", mutate: func(t *testing.T, target string) { writeReplacementFixture(t, target, changedBytes) }},
		{name: "unknown entry", mutate: func(t *testing.T, target string) {
			writeReplacementFixture(t, filepath.Join(target+replacementSuffix, "unrelated"), "keep")
		}},
		{name: "changed backup", mutate: func(t *testing.T, target string) { writeReplacementFixture(t, target+backupSuffix, changedBytes) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target, candidate := replacementFixture(t)
			if _, err := installBinary(target, candidate); err != nil {
				t.Fatal(err)
			}
			if tt.mutate != nil {
				tt.mutate(t, target)
			}
			current, err := binaryDigest(target)
			if err != nil {
				t.Fatal(err)
			}
			backup, err := binaryDigest(target + backupSuffix)
			if err != nil {
				t.Fatal(err)
			}
			writeReplacementFixture(t, candidate, originalBytes)
			if _, err := installBinary(target, candidate); err == nil {
				t.Fatal("update accepted retained recovery")
			}
			if tt.mutate != nil {
				if _, err := rollback(target); err == nil {
					t.Fatal("rollback accepted unrecognized state")
				}
				got, err := binaryDigest(target)
				if err != nil || got != current {
					t.Fatalf("refusal changed target: %s %v", got, err)
				}
			}
			got, err := binaryDigest(target + backupSuffix)
			if err != nil || got != backup {
				t.Fatalf("refusal changed backup: %s %v", got, err)
			}
		})
	}
}

// Simultaneous starts after an update all try to finish the same cleanup. Only
// real failures may surface; losing the race to another process is not one.
func TestReplacementConcurrentCleanup(t *testing.T) {
	for round := 0; round < 50; round++ {
		target, candidate := replacementFixture(t)
		if err := replaceRunningBinary(candidate, target, replacementOps{move: simulatedMove}); err != nil {
			t.Fatal(err)
		}
		errs := make([]error, 4)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = cleanupReplacement(target, replacementOps{})
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if _, err := os.Lstat(target + replacementSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovery directory remains: %v", err)
		}
	}
}
