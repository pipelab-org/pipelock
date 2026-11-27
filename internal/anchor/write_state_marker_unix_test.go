// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package anchor

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWriteStateMarkerFileDoesNotReplaceImmutableIdentity(t *testing.T) {
	dir := t.TempDir()
	marker := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Unix(1, 0).UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "first.json",
	}
	first, err := json.Marshal(marker)
	if err != nil {
		t.Fatalf("Marshal first marker: %v", err)
	}
	if err := writeStateMarkerFile(dir, marker, append(first, '\n')); err != nil {
		t.Fatalf("writeStateMarkerFile first: %v", err)
	}
	replacement := marker
	replacement.BundlePath = "replacement.json"
	second, err := json.Marshal(replacement)
	if err != nil {
		t.Fatalf("Marshal replacement marker: %v", err)
	}
	if err := writeStateMarkerFile(dir, marker, append(second, '\n')); err == nil {
		t.Fatalf("writeStateMarkerFile replacement err = %v, want immutable identity collision", err)
	}
	path, err := StateMarkerPath(dir, marker)
	if err != nil {
		t.Fatalf("StateMarkerPath: %v", err)
	}
	got, found, err := LoadStateMarkerFile(path)
	if err != nil || !found || got.BundlePath != marker.BundlePath {
		t.Fatalf("immutable marker = (%+v, %v, %v), want original bundle path %q", got, found, err, marker.BundlePath)
	}
}

// markerChildDirEnv carries the marker directory to the re-executed
// child that runs WriteStateMarker under a zero RLIMIT_FSIZE.
const markerChildDirEnv = "PIPELOCK_ANCHOR_MARKER_CHILD_DIR"

// TestWriteStateMarkerRejectsTempFileWriteFailure lowers RLIMIT_FSIZE in a
// re-executed child. The limit is process-wide, so lowering it here would also
// limit the test harness's own log writes and fail the package run with
// "file too large". The parent never changes its own limit.
func TestWriteStateMarkerRejectsTempFileWriteFailure(t *testing.T) {
	if dir := os.Getenv(markerChildDirEnv); dir != "" {
		writeStateMarkerUnderZeroFileSizeLimit(t, dir)
		return
	}

	var before syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &before); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	dir := t.TempDir()
	cmd := exec.CommandContext(t.Context(), os.Args[0], // #nosec G204,G702 -- controlled re-exec of this test binary.
		"-test.run=^TestWriteStateMarkerRejectsTempFileWriteFailure$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), markerChildDirEnv+"="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("temp write failure child: %v\n%s", err, out)
	}
	// A filter that matched nothing would also exit zero, so require the
	// child's own pass line.
	if !strings.Contains(string(out), "--- PASS: TestWriteStateMarkerRejectsTempFileWriteFailure") {
		t.Fatalf("temp write failure child did not run the check:\n%s", out)
	}

	var after syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &after); err != nil {
		t.Fatalf("Getrlimit after child: %v", err)
	}
	if after != before {
		t.Fatalf("parent RLIMIT_FSIZE changed from %+v to %+v", before, after)
	}
	assertNoTempStateMarkers(t, dir)
}

// writeStateMarkerUnderZeroFileSizeLimit runs in the child process only. The
// lowered limit dies with the process, so nothing is restored.
func writeStateMarkerUnderZeroFileSizeLimit(t *testing.T, dir string) {
	t.Helper()
	signal.Ignore(syscall.SIGXFSZ)
	var limited syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	limited.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatalf("Setrlimit: %v", err)
	}

	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "write anchor-state temp file") {
		t.Fatalf("WriteStateMarker err = %v, want temp write failure", err)
	}
	assertNoTempStateMarkers(t, dir)
}

func assertNoTempStateMarkers(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "anchor-state.d", ".anchor-state-*.tmp"))
	if err != nil {
		t.Fatalf("Glob temp markers: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary marker files remained after write failure: %v", matches)
	}
}

func TestWriteStateMarkerRejectsUnwritableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatalf("Chmod unwritable dir: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(dir, 0o700)
	})
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	})
	if err == nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("WriteStateMarker err = %v, want permission failure", err)
	}
}

func TestWriteStateMarkerRejectsSymlinkRoot(t *testing.T) {
	outside := t.TempDir()
	root := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(outside, root); err != nil {
		t.Fatalf("Symlink root: %v", err)
	}
	err := WriteStateMarker(root, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "create anchor-state directory") {
		t.Fatalf("WriteStateMarker err = %v, want symlink root refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "anchor-state.d")); !os.IsNotExist(statErr) {
		t.Fatalf("symlink target anchor-state.d stat err = %v, want not exist", statErr)
	}
}

func TestWriteStateMarkerRejectsFileAtIndexDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.d"), []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile index blocker: %v", err)
	}
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "not a regular directory") {
		t.Fatalf("WriteStateMarker err = %v, want index directory refusal", err)
	}
}

func TestWriteStateMarkerRejectsUnreadableIndexDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	dir := t.TempDir()
	indexDir := filepath.Join(dir, "anchor-state.d")
	if err := os.Mkdir(indexDir, 0o750); err != nil {
		t.Fatalf("Mkdir index: %v", err)
	}
	if err := os.Chmod(indexDir, 0); err != nil {
		t.Fatalf("Chmod index: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(indexDir, 0o750)
	})
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("WriteStateMarker err = %v, want unreadable index refusal", err)
	}
}

func TestStateMarkerReadersRejectUnreadableRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatalf("Chmod unreadable root: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(dir, 0o700)
	})
	marker := StateMarker{
		SessionID: "proxy",
		RootHash:  strings.Repeat("a", 64),
	}
	if _, found, err := LoadIndexedStateMarker(dir, marker); err == nil || found || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("LoadIndexedStateMarker found=%v err=%v, want permission failure", found, err)
	}
	if _, _, err := LoadStateMarkersResilient(dir); err == nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("LoadStateMarkersResilient err=%v, want permission failure", err)
	}
}

func TestWriteStateMarkerRejectsUnreadableImmutableIdentity(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	dir := t.TempDir()
	marker := StateMarker{
		SessionID:    "proxy",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "original.json",
	}
	if err := WriteStateMarker(dir, marker); err != nil {
		t.Fatalf("WriteStateMarker original: %v", err)
	}
	path, err := StateMarkerPath(dir, marker)
	if err != nil {
		t.Fatalf("StateMarkerPath: %v", err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("Chmod immutable marker: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(path, 0o600)
	})

	replacement := marker
	replacement.BundlePath = "replacement.json"
	if err := WriteStateMarker(dir, replacement); err == nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("WriteStateMarker replacement err = %v, want permission failure", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restore marker permissions: %v", err)
	}
	got, found, err := LoadStateMarkerFile(path)
	if err != nil || !found || got.BundlePath != marker.BundlePath {
		t.Fatalf("immutable marker = (%+v, %v, %v), want original", got, found, err)
	}
}

func TestWriteStateMarkerRejectsSymlinkLatestPointer(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("WriteFile outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, legacyStateMarker)); err != nil {
		t.Fatalf("Symlink latest pointer: %v", err)
	}
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("WriteStateMarker err = %v, want symlink latest-pointer refusal", err)
	}
	root, openErr := os.OpenRoot(filepath.Dir(outside))
	if openErr != nil {
		t.Fatalf("OpenRoot outside: %v", openErr)
	}
	defer func() { _ = root.Close() }()
	got, readErr := root.ReadFile(filepath.Base(outside))
	if readErr != nil {
		t.Fatalf("ReadFile outside: %v", readErr)
	}
	if string(got) != "unchanged" {
		t.Fatalf("outside file = %q, want unchanged", got)
	}
}

func TestWriteStateMarkerRejectsSymlinkLock(t *testing.T) {
	// A hostile symlink pre-planted at the writer lock-file path must not be
	// followed: the lock open uses O_NOFOLLOW so acquisition fails closed and the
	// symlink target is never written through.
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.lock")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("WriteFile outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, stateMarkerLockFile)); err != nil {
		t.Fatalf("Symlink lock: %v", err)
	}
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil {
		t.Fatal("WriteStateMarker err = nil, want lock-open refusal on a symlinked lock file")
	}
	got, readErr := os.ReadFile(filepath.Clean(outside))
	if readErr != nil {
		t.Fatalf("ReadFile outside: %v", readErr)
	}
	if string(got) != "unchanged" {
		t.Fatalf("outside lock target = %q, want unchanged (never written through the symlink)", got)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, stateMarkerIndexDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("index dir stat err = %v, want not created after a failed lock", statErr)
	}
}

func TestWriteStateMarkerFileRejectsMissingIdentity(t *testing.T) {
	err := writeStateMarkerFile(t.TempDir(), StateMarker{
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}, []byte("{}\n"))
	if err == nil || !strings.Contains(err.Error(), "session_id is empty") {
		t.Fatalf("writeStateMarkerFile err = %v, want identity failure", err)
	}
}

func TestWriteFileUnderDirRejectsInvalidAndBlockedPaths(t *testing.T) {
	root := t.TempDir()
	rootFD, err := openAnchorDir(root)
	if err != nil {
		t.Fatalf("openAnchorDir: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(rootFD) })

	for _, rel := range []string{"", ".", filepath.Join("..", "bundle.json")} {
		t.Run(rel, func(t *testing.T) {
			if err := writeFileUnderDir(rootFD, rel, []byte("bundle")); err == nil {
				t.Fatalf("writeFileUnderDir(%q) err = nil, want rejection", rel)
			}
		})
	}

	if err := os.WriteFile(filepath.Join(root, "blocked"), []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	if err := writeFileUnderDir(rootFD, filepath.Join("blocked", "bundle.json"), []byte("bundle")); err == nil || !strings.Contains(err.Error(), "open anchor bundle directory") {
		t.Fatalf("writeFileUnderDir blocked parent err = %v, want open directory failure", err)
	}
}

func TestWriteFileUnderDirRejectsUnwritableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o500); err != nil { // #nosec G302 -- test needs searchable but unwritable directory permissions.
		t.Fatalf("Chmod root: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Chmod(root, 0o700)
	})
	rootFD, err := openAnchorDir(root)
	if err != nil {
		t.Fatalf("openAnchorDir: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(rootFD) })
	if err := writeFileUnderDir(rootFD, filepath.Join("nested", "bundle.json"), []byte("bundle")); err == nil || !strings.Contains(err.Error(), "create anchor bundle directory") {
		t.Fatalf("writeFileUnderDir unwritable root err = %v, want mkdir failure", err)
	}
}
