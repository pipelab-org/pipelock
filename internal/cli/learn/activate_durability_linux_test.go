// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/directorysync"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
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
		priorReceipts, err := os.ReadFile(filepath.Join(fixture.root, "first-receipts.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		prefix := append(bytes.Repeat([]byte(" "), fileLimit-receiptRoom-len(priorReceipts)), priorReceipts...)
		if err := os.WriteFile(receiptPath, prefix, 0o600); err != nil {
			t.Fatal(err)
		}
		signal.Ignore(unix.SIGXFSZ)
		var originalLimit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &originalLimit); err != nil {
			t.Fatal(err)
		}
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: fileLimit, Max: originalLimit.Max}); err != nil {
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

		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &originalLimit); err != nil {
			t.Fatal(err)
		}
		if err := run(lifecycleTestCmd(nil, nil), flags); err == nil || !strings.Contains(err.Error(), receiptPath) ||
			!strings.Contains(err.Error(), "retry with --receipt-out") {
			t.Fatalf("retry on incomplete receipt file = %v, want the path and recovery option", err)
		}
		unchanged, err := os.ReadFile(filepath.Clean(receiptPath))
		if err != nil || !bytes.Equal(unchanged, raw) {
			t.Fatalf("retry changed the interrupted receipt log: %v", err)
		}
		afterRetry, err := os.ReadFile(filepath.Clean(manifestPath))
		if err != nil || !bytes.Equal(afterRetry, before) {
			t.Fatalf("retry changed the active manifest: %v", err)
		}

		flags.receiptOut = filepath.Join(fixture.root, "recovered-receipts.jsonl")
		const retryID = "recovered-operation"
		flags.intentID, flags.authorizationID = retryID, retryID
		if err := run(lifecycleTestCmd(nil, nil), flags); err != nil {
			t.Fatal(err)
		}
		receipts := readLifecycleReceipts(t, flags.receiptOut)
		active := fixture.latestAccepted(t)
		if len(receipts) != 2 || active.Envelope.Body.Generation != 3 {
			t.Fatalf("recovery published %d receipts at generation %d", len(receipts), active.Envelope.Body.Generation)
		}
		for _, rcpt := range receipts {
			if rcpt.ActiveManifestHash != active.ManifestHash {
				t.Fatalf("receipt manifest %q, want %q", rcpt.ActiveManifestHash, active.ManifestHash)
			}
			var link struct {
				IntentID        string `json:"intent_id"`
				AuthorizationID string `json:"authorization_id"`
			}
			mustUnmarshalPayload(t, rcpt, &link)
			if (operation == "promote" && link.IntentID != retryID) || (operation == "rollback" && link.AuthorizationID != retryID) {
				t.Fatalf("receipt %s missing link to recovered operation: %+v", rcpt.PayloadKind, link)
			}
		}

		return
	}
	for _, operation := range []string{"promote", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			bin, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(10*time.Second))
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "-test.run=^TestLifecycleReceiptInterruptedAppendLeavesManifestUnchanged$") // #nosec G204 -- re-executes the current test binary.
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

func TestLifecycleReceiptPathWithSearchOnlyAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "search-only")
	existing := filepath.Join(parent, "receipts")
	if err := os.MkdirAll(existing, 0o750); err != nil {
		t.Fatal(err)
	}
	syncDir := func(dir string) error {
		if dir == parent {
			return os.ErrPermission
		}
		return directorysync.Sync(dir)
	}
	path := filepath.Join(existing, "activation.jsonl")
	if got, err := prepareLifecycleReceiptPath(path, syncDir); err != nil || got != path {
		t.Fatalf("prepare below an existing search-only ancestor = %q, %v", got, err)
	}
	path = filepath.Join(parent, "new-receipts", "activation.jsonl")
	if _, err := prepareLifecycleReceiptPath(path, syncDir); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("prepare with an unsynced new directory entry = %v, want access denied", err)
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

func TestLifecycleReceiptAppendSyncErrorsKeepActiveManifest(t *testing.T) {
	injected := errors.New("receipt append sync failed")
	for _, boundary := range []struct {
		name string
		sync lifecycleReceiptSync
		want string
	}{
		{"file", lifecycleReceiptSync{file: func(*os.File) error { return injected }}, "sync lifecycle receipts: receipt append sync failed"},
		{"directory", lifecycleReceiptSync{dir: func(string) error { return injected }}, "sync lifecycle receipt directory: receipt append sync failed"},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			fixture := newLifecycleTestFixture(t)
			first := fixture.putContract(t, "worker-a")
			second := fixture.putContract(t, "worker-b")
			if err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(first, "worker-a", filepath.Join(fixture.root, "initial.jsonl"))); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(fixture.storeDir, "active.json")
			before, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			flags := fixture.promoteFlags(second, "worker-b", filepath.Join(fixture.root, "next.jsonl"))
			flags.receiptSync = boundary.sync
			err = runPromote(lifecycleTestCmd(nil, nil), flags)
			if !errors.Is(err, injected) || err.Error() != boundary.want {
				t.Fatalf("append error = %v, want %q", err, boundary.want)
			}
			after, err := os.ReadFile(filepath.Clean(path))
			if err != nil || !bytes.Equal(after, before) {
				t.Fatalf("active manifest changed after sync failure: %v", err)
			}
		})
	}
}
