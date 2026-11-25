// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	contract "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	legacy "github.com/luckyPipewrench/pipelock/internal/receipt"
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
		{"oversized legacy line", "unknown.jsonl", bytes.Repeat([]byte{' '}, recorder.MaxEntryLineBytes+1), false, true, 0, 0},
		{"oversized buffered record", "unknown.jsonl", bytes.Repeat([]byte{' '}, recorder.MaxEntryLineBytes+3), false, true, 0, 0},
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

func TestFailedLegacyGroupInventoryDropsProvisionalRows(t *testing.T) {
	v := verification{}
	presented := map[legacyIdentity]legacyPresentation{}
	grouped := v.verifyLegacyGroups(presented, func(visit func(legacy.ReceiptGroupResult) error) (legacy.ReceiptGroupInventoryResult, error) {
		group := legacy.ReceiptGroupResult{
			GroupID: "example", Verdict: legacy.GroupValid, CloseManifestSHA: strings.Repeat("a", 64), ShardCount: 1,
		}
		if err := visit(group); err != nil {
			t.Fatal(err)
		}
		return legacy.ReceiptGroupInventoryResult{Groups: 1}, recorder.ErrEvidenceChanged
	})
	if !grouped || len(presented) != 0 || len(v.result.Legacy) != 1 || v.result.Legacy[0].Verdict != string(legacy.GroupIncomplete) {
		t.Fatal("failed inventory published provisional group evidence")
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
	item := legacyPresentation{InventoryChain: InventoryChain{Seq: 5}, cliHead: "verified-root", cliSeq: seq, verdict: prefixVerdict}
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

func TestLegacyEndpointPinsEvidenceChainOfSelectedSession(t *testing.T) {
	const session = "selected-session"
	chains := map[legacyIdentity]legacyPresentation{
		{legacyAction, "action"}:     {session: session, InventoryChain: InventoryChain{Format: legacyAction}, cliHead: "action-root", cliSeq: 7, verdict: prefixVerdict},
		{legacyEvidence, "evidence"}: {session: session, InventoryChain: InventoryChain{Format: legacyEvidence}, cliHead: "evidence-root", cliSeq: 2, verdict: prefixVerdict},
	}
	for _, tc := range []struct {
		name, head string
		seq        uint64
		met        bool
	}{
		{"evidence endpoint", "evidence-root", 2, true},
		{"action endpoint is not the pinned chain", "action-root", 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seq := tc.seq
			v := verification{opts: Options{
				LegacySelection: LegacySelection{Session: session},
				LegacyEnd:       &LegacyEnd{Head: tc.head, Sequence: &seq},
			}}
			if err := v.verifyLegacyEndpoint(chains); err != nil {
				t.Fatalf("selected session with both chains: %v", err)
			}
			if met := !hasFinding(v.result, codeExpectationNotMet); met != tc.met {
				t.Fatalf("endpoint met = %v, want %v: %+v", met, tc.met, v.result)
			}
		})
	}
}

func TestLegacyContinuityReadFailure(t *testing.T) {
	v := verification{}
	v.verifyLegacyContinuity(filepath.Join(t.TempDir(), "missing"), "example", nil, false, nil, func() bool { return true })
	if !hasFinding(v.result, codeLegacyInvalid) || len(v.result.Legacy) != 1 ||
		v.result.Legacy[0].Verdict != "RESTART CONTINUITY INCOMPLETE" || v.result.Legacy[0].Class != legacyFailure {
		t.Fatalf("continuity diagnostic: %+v", v.result)
	}
}

func TestLegacySelectionWithMixedChains(t *testing.T) {
	const session = "selected-session"
	const group = "selected-group"
	const head = "verified-root"
	chains := map[legacyIdentity]legacyPresentation{
		{legacyGroup, group}:         {},
		{legacyAction, "other"}:      {session: "other-session", InventoryChain: InventoryChain{Format: legacyAction}, cliHead: "other-root"},
		{legacyEvidence, "selected"}: {session: session, InventoryChain: InventoryChain{Format: legacyEvidence}, cliHead: head, cliSeq: 2},
	}
	v := verification{opts: Options{
		LegacySelection: LegacySelection{Session: session, Group: group, Bindings: &contract.ChainVerifyOptions{}},
		LegacyEnd:       &LegacyEnd{Head: head, Sequence: new(uint64(2))},
	}}
	v.checkLegacySelection(chains)
	if err := v.verifyLegacyEndpoint(chains); err != nil {
		t.Fatal(err)
	}
	want := []Acceptance{
		{Kind: "expect-legacy-group", Value: group},
		{Kind: "expect-legacy-session", Value: session},
		{Kind: "expect-legacy-head", Value: head},
		{Kind: "expect-legacy-seq", Value: "2"},
	}
	if !reflect.DeepEqual(v.result.Accepted, want) || len(v.result.Findings) != 0 {
		t.Fatalf("mixed selection accepted = %+v, findings = %+v", v.result.Accepted, v.result.Findings)
	}

	for _, tc := range []struct {
		name      string
		selection LegacySelection
	}{
		{name: "session missing", selection: LegacySelection{Session: "missing"}},
		{name: "group missing", selection: LegacySelection{Group: "missing"}},
		{name: "bindings cannot select v1", selection: LegacySelection{Session: "other-session", Bindings: &contract.ChainVerifyOptions{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verification{opts: Options{LegacySelection: tc.selection}}
			v.checkLegacySelection(chains)
			if !hasFinding(v.result, codeExpectationNotMet) {
				t.Fatalf("selection accepted an unmet requirement: %+v", v.result)
			}
		})
	}
}

func TestLegacyEndpointRejectsMismatchedOrUnverifiedHead(t *testing.T) {
	target := legacyIdentity{legacyAction, "selected"}
	for _, tc := range []struct {
		name     string
		item     legacyPresentation
		mismatch bool
	}{
		{name: "different endpoint", item: legacyPresentation{verdict: prefixVerdict, cliHead: "different-root"}, mismatch: true},
		{name: "invalid chain", item: legacyPresentation{verdict: legacyInvalid, cliHead: "expected-root"}},
		{name: "forked chain", item: legacyPresentation{forked: true, cliHead: "expected-root"}},
		{name: "no verified history", item: legacyPresentation{InventoryChain: InventoryChain{Seq: -1}, cliHead: "expected-root"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verification{opts: Options{LegacyEnd: &LegacyEnd{Head: "expected-root"}}}
			chains := map[legacyIdentity]legacyPresentation{target: tc.item}
			if err := v.verifyLegacyEndpoint(chains); err != nil || len(v.result.Accepted) != 0 ||
				hasFinding(v.result, codeExpectationNotMet) != tc.mismatch {
				t.Fatalf("endpoint verification = %+v, %v", v.result, err)
			}
			if tc.mismatch && chains[target].verdict != legacyInvalid {
				t.Fatalf("mismatched endpoint did not invalidate the chain: %+v", chains[target])
			}
		})
	}
}

func TestLegacyEvidenceBindingsScope(t *testing.T) {
	raw, err := os.ReadFile(corpusRoot + "/../secret-egress-v1/valid-transformed-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := contract.ParseEvidenceReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, selected string
		invalid        bool
	}{
		{"binding applies to selected session", "example", true},
		{"binding leaves other sessions alone", "other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verification{opts: Options{LegacySelection: LegacySelection{
				Session: tc.selected, Bindings: &contract.ChainVerifyOptions{ExpectContractHash: Digest(nil)},
			}}, used: map[string]bool{}}
			batch := legacyBatch{session: "example", recorder: true, evidence: []contract.EvidenceReceipt{signed}}
			presented := map[legacyIdentity]legacyPresentation{}
			v.legacyEvidence(batch, nil, presented, map[legacyIdentity]map[int64]string{})
			if len(presented) != 1 || hasFinding(v.result, codeLegacyInvalid) != tc.invalid {
				t.Fatalf("presentation = %+v, findings = %+v", presented, v.result.Findings)
			}
			for _, item := range presented {
				if (item.verdict == legacyInvalid) != tc.invalid {
					t.Fatalf("verdict = %q, want invalid = %t", item.verdict, tc.invalid)
				}
			}
		})
	}
}

func TestMixedDirectoryEndorsedRotation(t *testing.T) {
	dir := t.TempDir()
	session, err := recorder.NewRunSessionID("proxy")
	if err != nil {
		t.Fatal(err)
	}
	root, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, successorPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	priorKey := hex.EncodeToString(root)
	for _, private := range []ed25519.PrivateKey{rootPrivate, successorPrivate} {
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, private)
		if err != nil {
			t.Fatal(err)
		}
		emitter := legacy.NewEmitter(legacy.EmitterConfig{
			Recorder: rec, PrivKey: private, Principal: "example", Actor: "example",
			Session: session, PriorSignerKeys: []string{priorKey},
		})
		emitErr := emitter.EmitSessionOpen()
		if err := errors.Join(emitter.InitError(), emitErr, rec.Close()); err != nil {
			t.Fatal(err)
		}
	}
	chain, err := legacy.ExtractReceiptsFromSessionDir(dir, session)
	if err != nil || len(chain) != 2 || chain[1].ActionRecord.KeyTransition == nil || chain[1].ActionRecord.ChainSeq != 0 {
		t.Fatalf("rotated chain must have two records and a sequence-zero transition, got %d records: %v", len(chain), err)
	}
	prior, successor := chain[0].ActionRecord, chain[1].ActionRecord
	successorHash, err := successor.Hash()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := canonicalJSON(Inventory{V: 1, Chains: []InventoryChain{{
		Chain: prior.RunNonce, Format: legacyAction, Record: legacyHash(successorHash),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := Digest(inventory)
	if err := os.WriteFile(filepath.Join(dir, InventoryFilename(digest)), inventory, 0o600); err != nil {
		t.Fatal(err)
	}
	stream := signedStream(t, 1, nil, &Cutover{Inventory: digest, Chains: 1})
	stream.close()
	stream.write(dir)
	// Pinning only the prior key cannot trust the successor's key transition.
	opts := Options{
		Directory: true, Keys: []ed25519.PublicKey{root, stream.public()}, AllowPrefix: true,
		LegacySelection: LegacySelection{Session: session},
	}
	result, err := VerifyPaths(t.Context(), []string{dir}, opts)
	if err != nil || result.ExitCode == 0 || result.Verdict == prefixVerdict || !hasFinding(result, codeLegacyInvalid) {
		t.Fatalf("rotation without the successor key pinned: %+v, %v", result, err)
	}
	// Pinning both keys verifies the rotated chain, and the cutover row matches
	// the whole chain even though the transition restarted chain_seq at zero.
	successorKey, err := hex.DecodeString(chain[1].SignerKey)
	if err != nil {
		t.Fatal(err)
	}
	opts.Keys = append(opts.Keys, ed25519.PublicKey(successorKey))
	result, err = VerifyPaths(t.Context(), []string{dir}, opts)
	wantAccepted := []Acceptance{{Kind: "allow-prefix", Value: "true"}, {Kind: "expect-legacy-session", Value: session}}
	if err != nil || result.ExitCode != 0 || result.Verdict != prefixVerdict ||
		!reflect.DeepEqual(result.Accepted, wantAccepted) || len(result.Legacy) != 1 ||
		result.Legacy[0].Class != legacyPass || result.Legacy[0].Chain != prior.RunNonce ||
		!hasFinding(result, codeLegacyEndUnproven) {
		t.Fatalf("rotation with both keys pinned: %+v, %v", result, err)
	}

	// In an unwrapped batch a fresh genesis splits the chain, while a
	// sequence-zero key transition stays with the preceding receipts.
	otherRaw, err := os.ReadFile(corpusRoot + "/../frozen/v1/action-receipt-v1-single.json")
	if err != nil {
		t.Fatal(err)
	}
	other, err := legacy.Unmarshal(otherRaw)
	if err != nil {
		t.Fatal(err)
	}
	batch := legacyBatch{action: append(chain, other)}
	v := verification{used: map[string]bool{}}
	presented := map[legacyIdentity]legacyPresentation{}
	v.legacyActions(batch, []string{chain[0].SignerKey, chain[1].SignerKey, other.SignerKey},
		presented, map[legacyIdentity]map[int64]string{})
	if len(presented) != 2 || hasFinding(v.result, codeLegacyInvalid) ||
		presented[legacyIdentity{legacyAction, prior.RunNonce}].Record != legacyHash(successorHash) {
		t.Fatalf("bare batch did not preserve both verified chains: %+v, %+v", presented, v.result.Findings)
	}
}

func TestLegacyPresentationCutoverPosition(t *testing.T) {
	for _, tc := range []struct {
		name, format, digest string
		seq                  int64
		forked, rotated      bool
		want                 int
	}{
		{"earlier action record after rotation", legacyAction, "sha256:middle", 1, false, true, 1},
		{"current action tail", legacyAction, "sha256:tail", 0, false, true, 0},
		{"unknown action record at same sequence", legacyAction, "sha256:other", 2, false, false, 0},
		{"fork without an earlier record", legacyAction, "sha256:middle", 2, true, false, 0},
		{"missing rotation boundary", legacyAction, "sha256:other", 0, false, false, 0},
		{"unrotated chain pinned beyond its tail", legacyAction, "sha256:other", 3, false, false, -1},
		{"rotated chain pinned beyond its tail", legacyAction, "sha256:other", 3, false, true, 0},
		{"rotated chain with a missing earlier digest", legacyAction, "sha256:other", 1, false, true, 0},
		{"earlier evidence record", legacyEvidence, "sha256:middle", 1, false, false, 1},
		{"missing evidence genesis digest", legacyEvidence, "sha256:other", 0, false, false, 1},
		{"later evidence sequence", legacyEvidence, "sha256:other", 3, false, false, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := legacyPresentation{
				InventoryChain: InventoryChain{Format: tc.format, Record: "sha256:tail", Seq: 2},
				position:       2, positions: map[int64]string{0: "first", 1: "middle", 2: "tail"},
				forked: tc.forked, rotated: tc.rotated,
			}
			if tc.name == "current action tail" || tc.name == "earlier action record after rotation" {
				p.Seq = 0
			}
			if got := p.compareCutoverPosition(InventoryChain{Record: tc.digest, Seq: tc.seq}); got != tc.want {
				t.Fatalf("cutover position = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestBareWrapperExclusionFollowsTheFileThatWasRead(t *testing.T) {
	const session = "example.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dir := t.TempDir()
	name := "evidence-" + session + "-0.jsonl"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("wrapper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stamps := sessionStamps([]string{path}, session)
	if len(stamps) != 1 || !stampsUnchanged(dir, stamps) {
		t.Fatalf("a file nobody touched changed: %v", stamps)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("ordinary shard\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if stampsUnchanged(dir, stamps) {
		t.Fatal("a same-name replacement kept the wrapper's exclusion")
	}
	v := &verification{opts: Options{}, result: newResult(Options{})}
	v.verifyLegacyContinuity(dir, "example", nil, false, map[string]bool{name: true}, func() bool { return stampsUnchanged(dir, stamps) })
	if len(v.result.Legacy) != 1 || v.result.Legacy[0].Verdict != "RESTART CONTINUITY INCOMPLETE" || !hasFinding(v.result, codeLegacyInvalid) {
		t.Fatalf("replaced wrapper was not reported: %+v %+v", v.result.Legacy, v.result.Findings)
	}
}

func TestLegacyDirectoryPreservesGroupAndBareWrapperVerdicts(t *testing.T) {
	for _, name := range []string{
		"g09-legacy-bare-evidence-under-run-name",
		"g09-group-with-tampered-shard",
		"g09-group-with-unclaimed-v3-content",
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(corpusRoot, name)
			recipe := readMutationRecipe(t, dir)
			keys, err := DecodeKeys(recipe.Keys)
			if err != nil {
				t.Fatal(err)
			}
			result, err := VerifyPaths(t.Context(), []string{dir}, Options{
				Directory: true, Keys: keys, AllowPrefix: recipe.AllowPrefix, AllowUnpinned: recipe.AllowUnpinned,
			})
			if err != nil {
				t.Fatalf("verify %s: %v", dir, err)
			}
			got, err := result.ResultBytes("projection")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "projection.json")
			want, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("verdict %q, exit %d: projection differs from %s", result.Verdict, result.ExitCode, path)
			}
		})
	}
}

func TestMissingBareWrapperStampCannotKeepExclusion(t *testing.T) {
	const session = "example"
	dir := t.TempDir()
	name := "evidence-" + session + "-0.jsonl"
	path := filepath.Join(dir, name)
	stamps := sessionStamps([]string{path}, session)
	if len(stamps) != 1 || stampsUnchanged(dir, stamps) {
		t.Fatal("a wrapper that could not be identified retained its exclusion")
	}
}
