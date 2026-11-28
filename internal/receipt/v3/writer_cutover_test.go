// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legacy "github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestStreamWriterCutoverCommitsAtFirstStream(t *testing.T) {
	dir := t.TempDir()
	opts := writerTestOptions(dir)
	source := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "frozen", "v1", "action-receipt-v1-chain.jsonl")
	raw, err := os.ReadFile(filepath.Clean(source))
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "evidence-conformance-session-0.jsonl")
	if err := os.WriteFile(old, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	batch, _, err := readLegacy(old)
	if err != nil || len(batch.action) == 0 {
		t.Fatalf("read legacy fixture: %v", err)
	}
	opts.PriorSignerKeys, err = DecodeKeys([]string{batch.action[0].SignerKey})
	if err != nil {
		t.Fatal(err)
	}
	journal := []byte("{\"defer_id\":\"example\",\"state\":\"resolved_block\"}")
	if err := os.WriteFile(filepath.Join(dir, legacyJournalName), journal, 0o600); err != nil {
		t.Fatal(err)
	}

	failure := errors.New("legacy receipt sync failed")
	refusingStorage := localWriterStorage()
	syncFile := refusingStorage.syncFile
	refusingStorage.syncFile = func(path string) error {
		if path == old {
			return failure
		}
		return syncFile(path)
	}
	requireCutoverRefusal(t, opts, refusingStorage, failure, "flush legacy receipt artifact")
	beforeSwitch, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range beforeSwitch {
		if _, ok := inventoryID(entry.Name()); ok {
			t.Fatal("unflushed legacy receipt was pinned by an inventory")
		}
	}

	storage := localWriterStorage()
	link := storage.link
	stopBeforeSwitch := errors.New("failed first stream link")
	storage.link = func(source, target string) error {
		if strings.HasSuffix(target, layoutFileSuffix) {
			return stopBeforeSwitch
		}
		return link(source, target)
	}
	if _, err := openStreamWriter(t.Context(), opts, storage); !errors.Is(err, stopBeforeSwitch) {
		t.Fatalf("expected failure after publishing inventory, got %v", err)
	}
	var inventoryPin string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if pin, ok := inventoryID(entry.Name()); ok {
			inventoryPin = pin
		}
	}
	if inventoryPin == "" || hasV3Entry(entries) {
		t.Fatalf("expected inventory without a v3 stream: %v", entries)
	}
	if claimed, checkErr := DirectoryHasV3(dir); checkErr != nil || claimed {
		t.Fatalf("uncommitted cutover inventory claimed directory: %t, %v", claimed, checkErr)
	}
	inventoryPath := filepath.Join(dir, InventoryFilename(inventoryPin))
	body, err := os.ReadFile(filepath.Clean(inventoryPath))
	if err != nil {
		t.Fatal(err)
	}
	stalePath := filepath.Join(dir, InventoryFilename(Digest([]byte("stale inventory"))))
	if err := os.WriteFile(stalePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	barrierErr := errors.New("cutover inventory barrier failed")
	for _, stage := range []string{"remove stale inventory", "flush inventory file", "flush inventory directory"} {
		t.Run(stage, func(t *testing.T) {
			storage := localWriterStorage()
			switch stage {
			case "remove stale inventory":
				remove := storage.remove
				storage.remove = func(path string) error {
					if path == stalePath {
						return barrierErr
					}
					return remove(path)
				}
			case "flush inventory file":
				syncFile := storage.syncFile
				storage.syncFile = func(path string) error {
					if path == inventoryPath {
						return barrierErr
					}
					return syncFile(path)
				}
			case "flush inventory directory":
				syncDir := storage.syncDir
				storage.syncDir = func(path string) error {
					if path == dir {
						return barrierErr
					}
					return syncDir(path)
				}
			}
			requireCutoverRefusal(t, opts, storage, barrierErr, "")
		})
	}

	if err := os.WriteFile(inventoryPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireCutoverRefusal(t, opts, localWriterStorage(), nil, "existing receipt cutover inventory failed verification")
	if err := os.Remove(inventoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(inventoryPath, 0o750); err != nil {
		t.Fatal(err)
	}
	requireCutoverRefusal(t, opts, localWriterStorage(), nil, "evidence path is not a regular file")
	if err := os.Remove(inventoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	restarted := requireWriter(t, opts, localWriterStorage())
	if got := restarted.open.LegacyCutover; got.Chains != 1 || got.Inventory != inventoryPin {
		t.Fatalf("cutover used the wrong inventory: %+v", got)
	}
	inventory, code, err := readInventory(filepath.Join(dir, InventoryFilename(inventoryPin)), *restarted.open.LegacyCutover, "")
	if err != nil || code != "" || inventory.Journal != Digest(append(journal, '\n')) {
		t.Fatalf("unexpected cutover inventory: %+v, %s, %v", inventory, code, err)
	}
	if err := restarted.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	keys := append(opts.PriorSignerKeys, opts.SigningKey.Public().(ed25519.PublicKey))
	result := verifyWritten(t, dir, keys...)
	if len(result.Legacy) != 1 || !hasFinding(result, codeLegacyEndUnproven) {
		t.Fatalf("legacy chain was not verified at cutover: %+v", result)
	}

	if err := os.WriteFile(filepath.Join(dir, legacyJournalName), []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted = requireWriter(t, opts, localWriterStorage())
	if err := restarted.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestStreamWriterRepairsInterruptedJournal(t *testing.T) {
	const held = "{\"defer_id\":\"example\",\"state\":\"deferred_held\"}\n"
	const damaged = "{\"defer_id\":"
	const invalid = `{"defer_id":"example","state":123}`
	for _, tc := range []struct {
		name string
		data string
		want string
		err  string
	}{
		{name: "pending with torn tail", data: held + damaged, want: held, err: "unresolved legacy holds"},
		{name: "pending without delimiter", data: strings.TrimSuffix(held, "\n"), want: held, err: "unresolved legacy holds"},
		{name: "malformed complete entry", data: held + damaged + "\n", want: held + damaged + "\n", err: "parse defer journal"},
		{name: "complete invalid entry without newline", data: invalid, want: invalid, err: "parse defer journal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, legacyJournalName), []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := writerTestOptions(dir)
			writer, err := OpenStreamWriter(t.Context(), opts)
			if err == nil {
				_ = writer.Close(t.Context(), nil)
				t.Fatalf("wanted %s, cutover succeeded", tc.err)
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("wanted %s, got %v", tc.err, err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			data, err := root.ReadFile(legacyJournalName)
			if err != nil || !bytes.Equal(data, []byte(tc.want)) {
				t.Fatalf("unexpected journal bytes %q (%v)", data, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("refused cutover left extra files: %v (%v)", entries, err)
			}
		})
	}
}

func TestStreamWriterInventoriesMoreThan1024LegacyChains(t *testing.T) {
	dir := t.TempDir()
	opts := writerTestOptions(dir)
	var chains bytes.Buffer
	for i := range 1025 {
		rec, err := legacy.Sign(legacy.ActionRecord{
			Version: legacy.ActionRecordVersion, ActionID: fmt.Sprintf("request-%d", i),
			ActionType: legacy.ActionRead,
			Timestamp:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Target:     "api.vendor.example", Verdict: "allow", Transport: "fetch", ChainPrevHash: "genesis",
		}, opts.SigningKey)
		if err != nil {
			t.Fatal(err)
		}
		line, err := legacy.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		chains.Write(line)
		chains.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "activation-receipts.jsonl"), chains.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := requireWriter(t, opts, localWriterStorage())
	pin := writer.open.LegacyCutover
	if pin.Chains != 1025 {
		t.Fatalf("cutover inventoried %d chains, want 1025", pin.Chains)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if len(result.Legacy) != 1025 {
		t.Fatalf("verified %d legacy chains, want 1025", len(result.Legacy))
	}
}

func TestInspectStartupChecksStoppedEvidenceWithPinnedKeys(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	keys := []ed25519.PublicKey{opts.SigningKey.Public().(ed25519.PublicKey)}
	if _, err := InspectStartup(t.Context(), opts.Dir, nil); err == nil {
		t.Fatal("inspection accepted unpinned evidence")
	}
	if _, err := InspectStartup(t.Context(), opts.Dir, keys); err == nil {
		t.Fatal("inspection accepted an active writer")
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := InspectStartup(t.Context(), opts.Dir, keys)
	if err != nil || result.Verdict != "VALID" {
		t.Fatalf("stopped evidence: verdict=%s error=%v", result.Verdict, err)
	}
}

func TestStreamWriterRefusesFailedJournalRepairBarriers(t *testing.T) {
	const (
		stageCreate        = "create"
		stageCopy          = "copy"
		stageSync          = "sync"
		stageRename        = "rename"
		stageDirectorySync = "directory sync"
	)
	const held = "{\"defer_id\":\"example\",\"state\":\"deferred_held\"}"
	failure := errors.New("journal repair storage failure")
	for _, stage := range []string{stageCreate, stageCopy, stageSync, stageRename, stageDirectorySync} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, legacyJournalName)
			if err := os.WriteFile(path, []byte(held), 0o600); err != nil {
				t.Fatal(err)
			}
			storage := localWriterStorage()
			create := storage.createTemp
			switch stage {
			case stageCreate:
				storage.createTemp = func(string, string) (StreamFile, error) { return nil, failure }
			case stageCopy, stageSync:
				storage.createTemp = func(dir, pattern string) (StreamFile, error) {
					file, err := create(dir, pattern)
					if err != nil {
						return nil, err
					}
					if stage == stageCopy {
						return errorWriterFile{StreamFile: file, writeErr: failure}, nil
					}
					return errorWriterFile{StreamFile: file, syncErr: failure}, nil
				}
			case stageRename:
				storage.rename = func(string, string) error { return failure }
			case stageDirectorySync:
				storage.syncDir = func(string) error { return failure }
			}
			w := &StreamWriter{dir: dir, storage: storage}
			if _, err := w.cutoverJournal(); !errors.Is(err, failure) {
				t.Fatalf("cutover error = %v, want injected failure", err)
			}
			want := held
			if stage == stageDirectorySync {
				want += "\n"
			}
			got, err := os.ReadFile(filepath.Clean(path))
			if err != nil || string(got) != want {
				t.Fatalf("journal after failed cutover: %q (%v), want %q", got, err, want)
			}
		})
	}
}

func requireCutoverRefusal(t *testing.T, opts StreamWriterOptions, storage writerStorage, cause error, diagnostic string) {
	t.Helper()
	writer, err := openStreamWriter(t.Context(), opts, storage)
	if err == nil {
		_ = writer.Close(t.Context(), nil)
		t.Fatal("cutover succeeded after inventory failure")
	}
	if cause != nil && !errors.Is(err, cause) || !strings.Contains(err.Error(), diagnostic) {
		t.Fatalf("cutover error = %v, want %v %q", err, cause, diagnostic)
	}
	if committed, inspectErr := DirectoryHasV3(opts.Dir); committed || inspectErr != nil {
		t.Fatalf("refused cutover left v3 evidence: %t, %v", committed, inspectErr)
	}
}

func TestStreamWriterRefusesUnverifiedLegacyCutover(t *testing.T) {
	const name = "activation-receipts.jsonl"
	for _, tc := range []struct {
		name, file, contents, diagnostic string
	}{
		{"malformed legacy receipt", name, "{\n", "receipt cutover refused"},
		{"unreadable legacy journal", legacyJournalName, "", "open legacy defer journal"},
		{"damaged committed v3 evidence", "damaged" + layoutFileSuffix, "{\n", "verify receipt history before restart"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.file)
			if tc.file == legacyJournalName {
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			writer, err := OpenStreamWriter(t.Context(), writerTestOptions(dir))
			if writer != nil {
				_ = writer.Close(t.Context(), nil)
			}
			if err == nil || !strings.Contains(err.Error(), tc.diagnostic) {
				t.Fatalf("startup error = %v, want %q", err, tc.diagnostic)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != tc.file {
				t.Fatalf("refused startup changed the inventory: %v, %v", entries, err)
			}
		})
	}
}

func TestStreamWriterRefusesUnflushedCompleteJournal(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	path := filepath.Join(opts.Dir, legacyJournalName)
	journal := "{\"defer_id\":\"example\",\"state\":\"resolved_block\"}\n"
	if err := os.WriteFile(path, []byte(journal), 0o600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("journal sync failed")
	storage := localWriterStorage()
	storage.syncFile = func(got string) error {
		if got != path {
			t.Fatalf("synced %q, want %q", got, path)
		}
		return failure
	}
	requireCutoverRefusal(t, opts, storage, failure, "flush legacy defer journal")
}

func TestStreamWriterRequiresExistingInventoryReflush(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "inventory file"
		if directory {
			name = "inventory directory"
		}
		t.Run(name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			body, err := canonicalJSON(Inventory{V: 1, Chains: []InventoryChain{}, Journal: Digest(nil)})
			if err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(opts.Dir, legacyJournalName)
			path := filepath.Join(opts.Dir, InventoryFilename(Digest(body)))
			for filename, content := range map[string][]byte{journal: nil, path: body} {
				if err := os.WriteFile(filename, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			storage := localWriterStorage()
			fault := errors.New("inventory flush failed")
			if directory {
				syncDir := storage.syncDir
				storage.syncDir = func(name string) error {
					if name == opts.Dir {
						return fault
					}
					return syncDir(name)
				}
			} else {
				syncFile := storage.syncFile
				storage.syncFile = func(name string) error {
					if name == path {
						return fault
					}
					return syncFile(name)
				}
			}
			requireCutoverRefusal(t, opts, storage, fault, "re-flush cutover inventory")
			got, err := os.ReadFile(filepath.Clean(path))
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("existing inventory changed: %q, %v", got, err)
			}
		})
	}
}

func TestStreamWriterRefusesUnflushedLegacyChainLink(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	fixture := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "parity", "rotated")
	source, err := os.OpenRoot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	var keys []string
	for _, name := range []string{"signer-key.hex", "rotated-signer-key.hex"} {
		key, err := source.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, strings.TrimSpace(string(key)))
	}
	opts.PriorSignerKeys, err = DecodeKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var link string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, legacy.ChainLinkFilePrefix) {
			link = filepath.Join(opts.Dir, name)
		} else if !legacyCandidate(name) {
			continue
		}
		body, err := source.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(opts.Dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if link == "" {
		t.Fatal("rotated fixture is missing its chain link")
	}
	failure := errors.New("legacy link sync failed")
	storage := localWriterStorage()
	syncFile := storage.syncFile
	storage.syncFile = func(path string) error {
		if path == link {
			return failure
		}
		return syncFile(path)
	}
	requireCutoverRefusal(t, opts, storage, failure, "flush legacy receipt artifact")
}
