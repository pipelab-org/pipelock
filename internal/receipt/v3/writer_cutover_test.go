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
	restarted := requireWriter(t, opts, localWriterStorage())
	if got := restarted.open.LegacyCutover; got.Chains != 1 || got.Inventory != inventoryPin {
		t.Fatalf("cutover used the wrong inventory: %+v", got)
	}
	inventory, code, err := readInventory(filepath.Join(dir, InventoryFilename(inventoryPin)), *restarted.open.LegacyCutover, "")
	if err != nil || code != "" || inventory.Journal != Digest(journal) {
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

func TestStreamWriterRepairsOnlyTornJournal(t *testing.T) {
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
