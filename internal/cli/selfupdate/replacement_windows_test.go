// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	releasetrust "github.com/luckyPipewrench/pipelock/internal/release"
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
