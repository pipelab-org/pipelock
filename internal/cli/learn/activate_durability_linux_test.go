// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/directorysync"
)

func TestLifecycleReceiptInterruptedAppendLeavesManifestUnchanged(t *testing.T) {
	const childMode = "PIPELOCK_TEST_LIFECYCLE_INTERRUPTED_APPEND"
	if operation := os.Getenv(childMode); operation != "" {
		fixture := newLifecycleTestFixture(t)
		first := fixture.putContract(t, "worker-a")
		second := fixture.putContract(t, "worker-b")
		flags := fixture.promoteFlags(first, "worker-a", filepath.Join(fixture.root, "first-receipts.jsonl"))
		if err := runPromote(lifecycleTestCmd(nil, nil), flags); err != nil {
			t.Fatal(err)
		}
		firstState := fixture.latestAccepted(t)
		flags = fixture.promoteFlags(second, "worker-b", filepath.Join(fixture.root, "second-receipts.jsonl"))
		if err := runPromote(lifecycleTestCmd(nil, nil), flags); err != nil {
			t.Fatal(err)
		}
		previous := fixture.latestAccepted(t)
		manifestPath := filepath.Join(fixture.storeDir, "active.json")
		before, err := os.ReadFile(filepath.Clean(manifestPath))
		if err != nil {
			t.Fatal(err)
		}

		receiptPath := filepath.Join(fixture.root, "limited-receipts.jsonl")
		const fileLimit = 64 << 10
		const receiptRoom = 1500
		if err := os.WriteFile(receiptPath, []byte(strings.Repeat(" ", fileLimit-receiptRoom)), 0o600); err != nil {
			t.Fatal(err)
		}
		signal.Ignore(unix.SIGXFSZ)
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: fileLimit, Max: fileLimit}); err != nil {
			t.Fatal(err)
		}

		flags = fixture.promoteFlags(first, "worker-a", receiptPath)
		run := runPromote
		if operation == "rollback" {
			flags.rollbackTarget = firstState.ManifestHash
			run = runRollback
		}
		err = run(lifecycleTestCmd(nil, nil), flags)
		if !errors.Is(err, unix.EFBIG) {
			t.Fatalf("operation error = %v, want file-size failure", err)
		}
		raw, err := os.ReadFile(filepath.Clean(receiptPath))
		if err != nil {
			t.Fatal(err)
		}
		if newlines := strings.Count(string(raw[fileLimit-receiptRoom:]), "\n"); newlines != 1 {
			t.Fatalf("interrupted append left %d complete receipt lines, want 1", newlines)
		}
		if after := fixture.latestAccepted(t); after.ManifestHash != previous.ManifestHash {
			t.Fatalf("manifest changed from generation %d to %d with only one complete receipt", previous.Envelope.Body.Generation, after.Envelope.Body.Generation)
		}
		after, err := os.ReadFile(filepath.Clean(manifestPath))
		if err != nil || !bytes.Equal(after, before) {
			t.Fatalf("active manifest changed after interrupted receipt append: %v", err)
		}

		return
	}
	for _, operation := range []string{"promote", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			bin, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), bin, "-test.run=^TestLifecycleReceiptInterruptedAppendLeavesManifestUnchanged$") // #nosec G204 -- re-executes the current test binary.
			cmd.Env = append(os.Environ(), childMode+"="+operation)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("interrupted %s: %v\n%s", operation, err, output)
			}
		})
	}
}

func TestLifecycleReceiptPathRetrySyncsExistingAncestors(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	path := filepath.Join(first, "second", "lifecycle.jsonl")
	syncErr := errors.New("interrupted directory sync")
	if _, err := prepareLifecycleReceiptPath(path, func(string) error { return syncErr }); !errors.Is(err, syncErr) {
		t.Fatalf("initial prepare error = %v, want %v", err, syncErr)
	}
	synced := make(map[string]bool)
	if _, err := prepareLifecycleReceiptPath(path, func(dir string) error {
		synced[dir] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, ancestor := range []string{root, first} {
		if !synced[ancestor] {
			t.Errorf("retry skipped directory sync for %s", ancestor)
		}
	}
}

func TestLifecycleReceiptPathCreatesNestedDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "first", "second", "lifecycle.jsonl")
	clean, err := prepareLifecycleReceiptPath(path, directorysync.Sync)
	if err != nil || clean != path {
		t.Fatalf("receipt path = %q, error = %v", clean, err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
		t.Fatalf("receipt directory mode = %v, error = %v", info, err)
	}
}
