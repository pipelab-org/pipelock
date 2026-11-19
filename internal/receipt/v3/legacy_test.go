// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contract "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestMixedDirectoryLegacyEvidenceIdentity(t *testing.T) {
	raw, err := os.ReadFile(corpusRoot + "/../secret-egress-v1/valid-transformed-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := contract.ParseEvidenceReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if signed.ChainSeq != 0 {
		t.Fatalf("frozen receipt must be genesis, got sequence %d", signed.ChainSeq)
	}
	hash, err := contract.ReceiptHash(signed)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	inventory, err := canonicalJSON(Inventory{V: 1, Chains: []InventoryChain{{
		Chain: legacyHash(hash), Record: legacyHash(hash), Format: legacyEvidence,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := Digest(inventory)
	for name, data := range map[string][]byte{
		"activation-receipts.jsonl": raw,
		InventoryFilename(digest):   inventory,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stream := signedStream(t, 1, nil, &Cutover{Inventory: digest, Chains: 1})
	stream.close()
	stream.write(dir)
	result, err := VerifyPaths(t.Context(), []string{dir}, Options{Directory: true, AllowUnpinned: true})
	if err != nil || result.Verdict != prefixVerdict || len(result.Legacy) != 1 ||
		result.Legacy[0].Chain != legacyHash(hash) || !hasFinding(result, codeLegacyEndUnproven) {
		t.Fatalf("unexpected legacy result: %+v, %v", result, err)
	}
}

func TestLegacyBatchDiscrimination(t *testing.T) {
	v1, err := os.ReadFile(corpusRoot + "/../frozen/v1/action-receipt-v1-single.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, v1); err != nil {
		t.Fatal(err)
	}
	v2, err := os.ReadFile(corpusRoot + "/../secret-egress-v1/valid-transformed-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	serialize := func(kind, prev string, raw []byte) []byte {
		t.Helper()
		entry := recorder.Entry{
			Version: 1, Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			SessionID: "example", Type: kind, Transport: "mcp", Summary: "example",
			Detail: json.RawMessage(raw), RawDetail: raw, PrevHash: prev,
		}
		entry.Hash = recorder.ComputeHash(entry)
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	operational := serialize("operation", recorder.GenesisHash, []byte("{}"))
	signed := serialize("evidence_receipt", recorder.GenesisHash, v2)
	for _, tc := range []struct {
		name, file    string
		data          []byte
		recorder, bad bool
		v1, v2        int
	}{
		{"bare action", "action.jsonl", append([]byte{'\n'}, compact.Bytes()...), false, false, 1, 0},
		{"bare evidence", "typed.jsonl", v2, false, false, 0, 1},
		{"legacy recorder", "evidence-example-0.jsonl", signed, true, false, 0, 1},
		{"operational recorder", "evidence-example-0.jsonl", operational, true, false, 0, 0},
		{"unknown format", "unknown.jsonl", []byte("{}"), false, false, 0, 0},
		{"mixed record types", "mixed.jsonl", bytes.Join([][]byte{compact.Bytes(), v2}, []byte{'\n'}), false, true, 0, 0},
		{"invalid JSON", "bad.jsonl", []byte("{"), false, true, 0, 0},
		{"invalid action", "bad.jsonl", []byte("{\"version\":1,\"action_record\":[]}"), false, true, 0, 0},
		{"invalid evidence", "bad.jsonl", []byte("{\"record_type\":\"evidence_receipt_v2\",\"signature\":[]}"), false, true, 0, 0},
		{"invalid recorder fields", "bad.jsonl", []byte("{\"session_id\":\"example\",\"type\":\"operation\"}"), false, true, 0, 0},
		{"wrong shard name", "evidence-other-0.jsonl", signed, false, true, 0, 0},
		{"wrong genesis", "evidence-example-0.jsonl", serialize("operation", "wrong", []byte("{}")), false, true, 0, 0},
		{"wrong recorder hash", "evidence-example-0.jsonl", bytes.Replace(signed, []byte("\"summary\":\"example\""), []byte("\"summary\":\"changed\""), 1), false, true, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.file)
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			batch, wrapped, err := readLegacy(path)
			if (err != nil) != tc.bad || (!tc.bad && (wrapped != tc.recorder || len(batch.action) != tc.v1 || len(batch.evidence) != tc.v2)) {
				t.Fatalf("wrapped %t, v1 %d, v2 %d, error %v", wrapped, len(batch.action), len(batch.evidence), err)
			}
		})
	}
}

func TestLegacyPositionBoundsAndConflictingCopies(t *testing.T) {
	key := legacyIdentity{legacyAction, Digest(nil)}
	positions := map[legacyIdentity]map[int64]string{}
	presented := map[legacyIdentity]legacyPresentation{}
	v := verification{}
	saveLegacyPosition(positions, key, 0, "first")
	saveLegacyPosition(positions, key, 0, "other")
	v.saveLegacy(presented, positions, key, 0, "other", true, prefixVerdict)
	if !presented[key].forked {
		t.Fatal("conflicting receipt copies were accepted as identical")
	}
	saveLegacyPosition(positions, key, maxInteger+1, "past-bound")
	v.saveLegacy(presented, positions, key, maxInteger+1, "past-bound", true, prefixVerdict)
	if !hasFinding(v.result, codeLegacyInvalid) {
		t.Fatal("out-of-range sequence was accepted")
	}
}

func TestLegacyNeedsDirectoryScopeForCutover(t *testing.T) {
	raw, err := os.ReadFile(corpusRoot + "/../secret-egress-v1/valid-transformed-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.jsonl")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	root := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	root.close()
	stream := root.write(dir)
	for _, tc := range []struct {
		name, want string
		paths      []string
	}{
		{"legacy only", "legacy verification path", []string{path}},
		{"mixed files", "require directory scope", []string{path, stream}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyPaths(t.Context(), tc.paths, Options{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}
