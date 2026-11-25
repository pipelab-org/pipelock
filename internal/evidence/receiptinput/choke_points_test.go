// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package receiptinput_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	v3 "github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/report"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestLegacyEvidenceChokePoints(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o750); err != nil {
		t.Fatal(err)
	}
	path, _ := testreceipt.V3(t, child, true)
	loc := recorder.EvidenceLocation{Root: root, ID: "child", Dir: child}
	noop := func(recorder.Entry) error { return nil }
	for _, tc := range []struct {
		name  string
		check func() error
	}{
		{"discover", func() error { _, err := recorder.DiscoverEvidenceLocations(root); return err }},
		{"resolve", func() error { _, err := recorder.ResolveEvidenceLocation(root, "child"); return err }},
		{"list", func() error { _, err := recorder.ListSessions(root); return err }},
		{"bounded list", func() error { _, err := recorder.ListSessionsBounded(root, 1); return err }},
		{"resolved list", func() error { _, err := recorder.ListSessionsBoundedResultResolved(loc, 0); return err }},
		{"resolved contents", func() error { _, err := recorder.ReadEvidenceLocationEntries(loc); return err }},
		{"walk", func() error { return recorder.WalkHistorySessions(root, func(string) error { return nil }) }},
		{"resolved walk", func() error { return recorder.WalkSessionHistoryResolved(loc, "proxy", noop) }},
		{"group present", func() error { _, err := receipt.ReceiptGroupEvidencePresent(child, 0); return err }},
		{"verify groups", func() error { _, err := receipt.VerifyReceiptGroups(child, nil, nil); return err }},
		{"group terminal", func() error { _, _, err := receipt.FindTerminalReceiptGroup(child, "proxy", nil); return err }},
		{"base listing", func() error { _, err := receipt.ContinuityBases(child); return err }},
		{"directory health", func() error { _, err := recorder.EvidenceDirectoryHealthForDir(child, 0); return err }},
		{"bounded location file", func() error {
			_, err := recorder.ReadEvidenceLocationFileBounded(loc, filepath.Base(path), 1024)
			return err
		}},
		{"bounded head", func() error { _, _, err := recorder.ReadHeadEntriesBounded(path, 1, 1024); return err }},
		{"recorder file", func() error { _, err := recorder.ReadEntries(path); return err }},
		{"history file", func() error { _, err := recorder.ReadHistoryEntries(path); return err }},
		{"legacy receipts", func() error { _, err := receipt.ExtractReceipts(path); return err }},
		{"contract receipts", func() error { _, err := contractreceipt.ExtractEvidenceReceipts(path); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.check()
			if !errors.Is(err, recorder.ErrLegacyEvidenceFormat) || !strings.Contains(err.Error(), filepath.Base(path)) {
				t.Fatalf("expected named profile refusal, got %v", err)
			}
		})
	}
	result := receipt.VerifyReceiptGroup(child, strings.Repeat("a", 32), nil)
	if result.Verdict == receipt.GroupValid || !strings.Contains(result.Error, filepath.Base(path)) {
		t.Fatal("single group verification did not identify the claimed file")
	}
}

func TestBoundedDiscoveryScreensNamesOutsideResult(t *testing.T) {
	dir := t.TempDir()
	for i := range 200 {
		name := fmt.Sprintf("evidence-session-%03d-0.jsonl", i)
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const profile = "sample.receipt-v4.jsonl"
	if err := os.WriteFile(filepath.Join(dir, profile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := recorder.OpenEvidenceDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	initial, err := handle.ReadDir(2)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range initial {
		if entry.Name() == profile {
			t.Skip("filesystem listed the profile inside the initial read")
		}
	}
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	if _, _, err := recorder.ReadEvidenceLocationEntriesBounded(location, 1); !errors.Is(err, recorder.ErrLegacyEvidenceFormat) ||
		!strings.Contains(err.Error(), profile) {
		t.Fatalf("expected named refusal beyond the result cap, got %v", err)
	}
}

func TestLegacyDecodersRefuseProfileContent(t *testing.T) {
	path, _ := testreceipt.V3(t, t.TempDir(), false)
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	data := append([]byte("\n \t "), raw...)
	legacyName := filepath.Join(t.TempDir(), "evidence-proxy-0.jsonl")
	if err := os.WriteFile(legacyName, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		check func() error
	}{
		{"entry", func() error { _, err := recorder.ParseEntryLine(data); return err }},
		{"recorder bytes", func() error { _, err := recorder.ReadEntriesFromReader(bytes.NewReader(data)); return err }},
		{"history bytes", func() error { _, err := recorder.ReadHistoryEntriesFromReader(bytes.NewReader(data)); return err }},
		{"recorder file", func() error { _, err := recorder.ReadEntries(legacyName); return err }},
		{"raw receipt", func() error { _, err := receipt.Unmarshal(line); return err }},
		{"v1 bytes", func() error { return receipt.VerifyV1BytesWithKey(line, "") }},
		{"v2 bytes", func() error { return contractreceipt.VerifyV2BytesWithKey(line, nil, "") }},
		{"legacy bytes", func() error { _, err := receipt.ExtractReceiptsBytes(data); return err }},
		{"legacy file", func() error { _, err := receipt.ExtractReceipts(legacyName); return err }},
		{"raw contract receipt", func() error { _, err := contractreceipt.ParseEvidenceReceipt(line); return err }},
		{"contract bytes", func() error { _, err := contractreceipt.ExtractEvidenceReceiptsBytes(data); return err }},
		{"contract file", func() error { _, err := contractreceipt.ExtractEvidenceReceipts(legacyName); return err }},
		{"audit report", func() error { _, err := report.ParseEvents(bytes.NewReader(data), report.ParseOptions{}); return err }},
		{"audit payload", func() error { return receiptinput.RefusePayload(data, "audit", "audit reader") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); !errors.Is(err, recorder.ErrLegacyEvidenceFormat) {
				t.Fatalf("expected profile refusal, got %v", err)
			}
		})
	}
}

func TestRefuseTreeReportsUnreadableDescendant(t *testing.T) {
	for _, target := range []string{"directory", "candidate file"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			child := filepath.Join(root, "child")
			if err := os.Mkdir(child, 0o750); err != nil {
				t.Fatal(err)
			}
			path := child
			if target == "candidate file" {
				path = filepath.Join(child, "evidence-proxy-0.jsonl")
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			if target == "directory" {
				t.Cleanup(func() {
					_ = os.Chmod(child, 0o700) // #nosec G302 -- restore access to the test directory for cleanup.
				})
			}
			if handle, err := os.Open(filepath.Clean(path)); err == nil {
				_ = handle.Close()
				t.Skip("process can still open the unreadable fixture")
			}
			if err := receiptinput.RefuseTree(root, "test reader", "evidence"); !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("expected a permission error for the descendant, got %v", err)
			}
		})
	}
}

func TestLegacyDirectoryWithLeftoverCutoverInventoryAllowed(t *testing.T) {
	dir := t.TempDir()
	// Simulate a legacy directory after a cutover attempt that wrote an inventory
	// file and failed before publishing the first .receipt-v3.jsonl stream.
	inventoryName := v3.InventoryFilename(v3.Digest([]byte(`{"chains":[],"v":1}`)))
	if err := os.WriteFile(filepath.Join(dir, inventoryName), []byte(`{"chains":[],"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "receipt-v3-cutover-notes.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes-receipt-v3.txt"), []byte("operator notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".receipt-v3.tmp"), []byte("temp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), []byte(`{"v":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if claimed, err := v3.ClaimsInput(dir, true); err != nil || claimed {
		t.Fatalf("v3.ClaimsInput = %t, %v; want false, nil", claimed, err)
	}
	if hasV3, err := v3.DirectoryHasV3(dir); err != nil || hasV3 {
		t.Fatalf("v3.DirectoryHasV3 = %t, %v; want false, nil", hasV3, err)
	}
	if err := receiptinput.RefuseTree(dir, "legacy reader", "legacy evidence"); err != nil {
		t.Fatalf("RefuseTree refused legacy directory with leftover cutover inventory: %v", err)
	}
	if err := recorder.RefuseReceiptDirectory(dir); err != nil {
		t.Fatalf("RefuseReceiptDirectory refused legacy directory: %v", err)
	}
	if _, err := recorder.DiscoverEvidenceLocations(dir); err != nil {
		t.Fatalf("DiscoverEvidenceLocations failed: %v", err)
	}
	if _, err := recorder.ListSessions(dir); err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if _, err := recorder.EvidenceDirectoryHealthForDir(dir, 0); err != nil {
		t.Fatalf("EvidenceDirectoryHealthForDir failed: %v", err)
	}
	ran := false
	if err := recorder.WithEvidenceWriterCeremonyLock(dir, func() error {
		ran = true
		return nil
	}); err != nil || !ran {
		t.Fatalf("WithEvidenceWriterCeremonyLock failed: ran=%t err=%v", ran, err)
	}
}
