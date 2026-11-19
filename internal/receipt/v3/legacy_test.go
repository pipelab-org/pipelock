// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"encoding/json"
	"errors"
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

func TestReadLegacyRefusesDisappearedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.jsonl")
	if _, _, err := readLegacy(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read missing legacy evidence: got %v, want %v", err, os.ErrNotExist)
	}
}

func TestLegacyPositionBoundsAndConflictingCopies(t *testing.T) {
	key := legacyIdentity{legacyAction, Digest(nil)}
	positions := map[legacyIdentity]map[int64]string{}
	presented := map[legacyIdentity]legacyPresentation{}
	v := verification{}
	saveLegacyPosition(positions, key, 0, "first")
	saveLegacyPosition(positions, key, 0, "other")
	v.saveLegacy(presented, positions, legacyPresentation{
		InventoryChain: InventoryChain{Chain: key.chain, Format: key.format, Record: legacyHash("other")},
		verdict:        prefixVerdict,
	}, 0, true)
	if !presented[key].forked {
		t.Fatal("conflicting receipt copies were accepted as identical")
	}
	saveLegacyPosition(positions, key, maxInteger+1, "past-bound")
	v.saveLegacy(presented, positions, legacyPresentation{
		InventoryChain: InventoryChain{Chain: key.chain, Format: key.format, Record: legacyHash("past-bound")},
		verdict:        prefixVerdict,
	}, maxInteger+1, true)
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

func TestLegacyDiagnosticLabels(t *testing.T) {
	for _, tc := range []struct {
		name, format, verdict string
		opts                  Options
		class, label          string
	}{
		{"closed without pin", legacyAction, "VALID", Options{}, legacyFailure, "CHAIN UNPINNED"},
		{"closed with unpinned opt-in", legacyAction, "VALID", Options{AllowUnpinned: true}, legacyPass, "CHAIN UNPINNED"},
		{"evidence chain broken", legacyEvidence, "INVALID", Options{}, legacyFailure, "EVIDENCE CHAIN BROKEN"},
		{"prefix refused", legacyEvidence, prefixVerdict, Options{AllowUnpinned: true}, legacyFailure, prefixVerdict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verification{opts: tc.opts}
			row := v.legacyResult(legacyPresentation{InventoryChain: InventoryChain{Format: tc.format}, verdict: tc.verdict})
			if row.Class != tc.class || row.Verdict != tc.label {
				t.Fatalf("legacy class and label: %+v", row)
			}
		})
	}
	v := verification{}
	v.failedLegacy("example", recorder.ErrEvidenceChanged)
	if v.result.Legacy[0].Verdict != "CHAIN UNAVAILABLE" || v.result.Legacy[0].Class != legacyFailure {
		t.Fatalf("unavailable legacy row: %+v", v.result.Legacy[0])
	}
}

func TestLegacyInvalidGroupInventoryLabel(t *testing.T) {
	dir := t.TempDir()
	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	stream.close()
	stream.write(dir)
	if err := os.WriteFile(filepath.Join(dir, "receipt-group-unknown.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyPaths(t.Context(), []string{dir}, Options{Directory: true, AllowUnpinned: true})
	if err != nil || !hasFinding(result, codeLegacyInvalid) || len(result.Legacy) != 1 ||
		result.Legacy[0].Verdict != "GROUP_INVALID" || result.Legacy[0].Class != legacyFailure {
		t.Fatalf("unexpected group inventory result: %+v, %v", result, err)
	}
}

func TestLegacyEndpointSelection(t *testing.T) {
	seq := uint64(2)
	first := legacyIdentity{legacyAction, "first"}
	second := legacyIdentity{legacyEvidence, "second"}
	item := legacyPresentation{InventoryChain: InventoryChain{Seq: 2}, cliHead: "verified-root", verdict: prefixVerdict}
	for _, tc := range []struct {
		name                string
		keys                []legacyIdentity
		unreadable, wantErr bool
		accepted            int
	}{
		{"missing", nil, false, true, 0},
		{"ambiguous", []legacyIdentity{first, second}, false, true, 0},
		{"unavailable", nil, true, false, 0},
		{"one matching chain", []legacyIdentity{first}, false, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verification{opts: Options{LegacyEnd: &LegacyEnd{Head: item.cliHead, Sequence: &seq}}}
			if tc.unreadable {
				v.failedLegacy(first.chain, recorder.ErrEvidenceChanged)
			}
			presented := map[legacyIdentity]legacyPresentation{}
			for _, key := range tc.keys {
				presented[key] = item
			}
			if err := v.verifyLegacyEndpoint(presented); (err != nil) != tc.wantErr || len(v.result.Accepted) != tc.accepted {
				t.Fatalf("legacy endpoint result: accepted=%+v, error=%v", v.result.Accepted, err)
			}
		})
	}
}

func TestLegacyContinuityReadFailure(t *testing.T) {
	v := verification{}
	v.verifyLegacyContinuity(filepath.Join(t.TempDir(), "missing"), "example", nil, false)
	if !hasFinding(v.result, codeLegacyInvalid) || len(v.result.Legacy) != 1 ||
		v.result.Legacy[0].Verdict != "RESTART CONTINUITY INCOMPLETE" || v.result.Legacy[0].Class != legacyFailure {
		t.Fatalf("continuity diagnostic: %+v", v.result)
	}
}
