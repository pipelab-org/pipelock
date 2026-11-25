// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"slices"
	"testing"
	"time"

	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	secondStream = "33333333333333333333333333333333"
	thirdStream  = "44444444444444444444444444444444"
)

func v3Successor(t *testing.T, parent *v3Stream, id, end string, seq int, edit func(v3Common)) *v3Stream {
	t.Helper()
	s := &v3Stream{id: id, lineage: parent.lineage, key: parent.key}
	body := v3DefaultOpen(s.key, s.lineage)
	delete(body, "legacy_cutover")
	record := v3.Digest(nil)
	if seq < len(parent.records) {
		record = parent.records[seq].id
	}
	body["previous"] = v3Common{"stream": parent.id, "ended": end, "seq": seq, "record": record}
	if edit != nil {
		edit(body)
	}
	s.add(t, "stream_open", body, nil)
	return s
}

func v3HistoryRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	root := v3New(t)
	root.close(t)
	rootFile := root.file(0, 2)
	unsealed := v3New(t)
	unsealedFile := unsealed.file(0, 1)
	second := v3Successor(t, root, secondStream, "closed", 1, nil)
	third := v3Successor(t, root, thirdStream, "closed", 1, nil)
	secondFile, thirdFile := second.finish(t), third.finish(t)
	unsealedSuccessor := v3Successor(t, unsealed, secondStream, "unsealed", 0, nil)
	openSuccessor := unsealedSuccessor.file(0, 1)
	closedSuccessor := unsealedSuccessor.finish(t)
	accept := v3Request{AcceptDiscontinuities: []string{unsealedSuccessor.records[0].id}}
	independent := &v3Stream{id: secondStream, lineage: root.lineage, key: root.key}
	independent.add(t, "stream_open", v3DefaultOpen(root.key, root.lineage), nil)
	fork := independent.finish(t)
	edited := func(end string, seq int, edit func(v3Common)) v3File {
		return v3Successor(t, root, secondStream, end, seq, edit).finish(t)
	}
	return []v3Recipe{
		{group: 4, name: "pinned-close", verdict: "VALID", files: []v3File{rootFile, secondFile}},
		{group: 4, name: "accepted-gap-open-successor", verdict: "VALID PREFIX, END UNPROVEN", code: "END_UNPROVEN", request: accept, files: []v3File{unsealedFile, openSuccessor}},
		{group: 4, name: "accepted-gap-closed-successor", verdict: "VALID, GAPS ACCEPTED", request: accept, files: []v3File{unsealedFile, closedSuccessor}},
		{group: 4, name: "root-fork", verdict: "INVALID", code: "ROOT_FORK", files: []v3File{rootFile, fork}},
		{group: 4, name: "succession-fork", verdict: "INVALID", code: "SUCCESSION_FORK", files: []v3File{rootFile, secondFile, thirdFile}},
		{group: 4, name: "lineage-mismatch", verdict: "INVALID", code: "LINEAGE_MISMATCH", files: []v3File{
			rootFile, edited("closed", 1, func(body v3Common) { body["lineage"] = thirdStream }),
		}},
		{group: 4, name: "predecessor-absent", verdict: "INCOMPLETE", code: "PREDECESSOR_NOT_PRESENTED", files: []v3File{secondFile}},
		{group: 4, name: "predecessor-truncated", verdict: "INVALID", code: "PREDECESSOR_TRUNCATED", files: []v3File{unsealedFile, secondFile}},
		{group: 4, name: "wrong-pin", verdict: "INVALID", code: "PIN_MISMATCH", files: []v3File{
			rootFile, edited("closed", 1, func(body v3Common) { body["previous"].(v3Common)["record"] = v3.Digest(nil) }),
		}},
		{group: 4, name: "wrong-write-error-pin", verdict: "INVALID", code: "PIN_MISMATCH", files: []v3File{
			rootFile, edited("write_error", 0, func(body v3Common) { body["previous"].(v3Common)["record"] = v3.Digest(nil) }),
		}},
		{group: 4, name: "absent-max-write-error-pin", verdict: "INVALID", code: "PREDECESSOR_TRUNCATED", files: []v3File{
			rootFile, edited("write_error", 0, func(body v3Common) {
				body["previous"].(v3Common)["seq"] = int64(1<<53 - 1)
			}),
		}},
		{group: 4, name: "tail-after-pin", verdict: "INVALID", code: "TAIL_AFTER_SUCCESSION", files: []v3File{rootFile, edited("unsealed", 0, nil)}},
		{group: 4, name: "disconnected", verdict: "INCOMPLETE", code: "HISTORY_DISCONNECTED", files: []v3File{secondFile, thirdFile}},
		{group: 4, name: "unconfirmed-tail", verdict: "VALID PREFIX, END UNPROVEN", code: "UNCONFIRMED", files: []v3File{rootFile, edited("write_error", 0, nil)}},
		{group: 4, name: "wrong-expectation", verdict: "INVALID", code: "EXPECTATION_NOT_MET", request: v3Request{ExpectLineage: thirdStream}, files: []v3File{rootFile}},
	}
}

func v3DecisionRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	action := v3DefaultAction
	correction := func() v3Common {
		a := action()
		a["phase"], a["effect_boundary"], a["effect_relation"] = "resolution", "approval_prompt", "after"
		a["hold"] = v3Common{"id": "approval", "resolution_policy": "example", "resolution_source": "example", "correction": true}
		return a
	}
	hold := func(verdict string) v3Common {
		a := action()
		a["phase"], a["effect_boundary"], a["effect_relation"], a["verdict"] = "hold", "approval_prompt", "before", verdict
		a["hold"] = v3Common{"id": "approval", "policy": "example"}
		if verdict == "ask" {
			a["ask"] = v3Common{"channel": "approval_api", "observed": true}
		}
		return a
	}
	resolution := func(verdict string) v3Common {
		a := correction()
		delete(a["hold"].(v3Common), "correction")
		a["verdict"] = verdict
		if verdict == "ask" {
			a["ask"] = v3Common{"channel": "approval_api", "observed": true}
		}
		return a
	}
	attempt := func(phase, verdict, relation, outcome string, number int) v3Common {
		a := action()
		a["phase"], a["verdict"], a["effect_boundary"], a["effect_relation"] = phase, verdict, "upstream_send", relation
		a["attempt"] = number
		if outcome != "" {
			a["outcome_class"] = outcome
		}
		return a
	}
	intent := func(n int) v3Common { return attempt("intent", "allow", "before", "", n) }
	outcome := func(class, relation string, n int) v3Common { return attempt("outcome", "allow", relation, class, n) }
	refusal := func(n int) v3Common { return attempt("outcome", "block", "not_attempted", "not_released", n) }
	var recipes []v3Recipe
	for _, row := range []struct {
		name  string
		valid bool
		rows  []v3Common
	}{
		{"repeat-decision", false, []v3Common{action(), action()}},
		{"correction-without-allow", false, []v3Common{hold("defer"), correction()}},
		{"unknown-hold", false, []v3Common{resolution("block")}},
		{"step-up", true, []v3Common{hold("ask"), resolution("ask")}},
		{"correcting-block", true, []v3Common{hold("defer"), resolution("allow"), correction(), correction()}},
		{"allow-after-block", false, []v3Common{hold("defer"), resolution("block"), resolution("allow")}},
		{"settlement-after-intent", false, []v3Common{hold("defer"), resolution("allow"), intent(1), correction()}},
		{"completed", true, []v3Common{hold("defer"), resolution("allow"), intent(1), outcome("completed", "after", 1)}},
		{"retry-after-refusal", true, []v3Common{refusal(1), intent(2), outcome("completed", "after", 2)}},
		{"retry-after-failed-before", true, []v3Common{intent(1), outcome("failed_before_attempt", "not_attempted", 1), intent(2)}},
		{"retry-after-failed-after", false, []v3Common{intent(1), outcome("failed_after_attempt", "after", 1), intent(2)}},
		{"attempt-unknown", true, []v3Common{intent(1), outcome("attempt_unknown", "unknown", 1)}},
		{"attempt-mismatch", false, []v3Common{intent(1), outcome("completed", "after", 2)}},
		{"standalone-outcome", false, []v3Common{outcome("completed", "after", 1)}},
	} {
		s := v3New(t)
		for _, body := range row.rows {
			s.add(t, "action", body, nil)
		}
		file := s.finish(t)
		if row.valid {
			recipes = append(recipes, v3Recipe{group: 5, name: row.name, verdict: "VALID", files: []v3File{file}})
		} else {
			recipes = append(recipes, v3Invalid(5, row.name, "DECISION_INCONSISTENT", file))
		}
	}
	return recipes
}

func v3CutoverRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	legacy, err := os.ReadFile("testdata/frozen/v1/action-receipt-v1-chain.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	const legacyName = "evidence-conformance-session-0.jsonl"
	entries, err := recorder.ReadHistoryEntriesFromReader(bytes.NewReader(legacy))
	if err != nil {
		t.Fatal(err)
	}
	chain, _, found, err := actionreceipt.RecorderFileChains(legacyName, entries)
	if err != nil || !found {
		t.Fatalf("read frozen recorder file: %v", err)
	}
	first, err := chain[0].ActionRecord.Hash()
	if err != nil {
		t.Fatal(err)
	}
	last := chain[len(chain)-1].ActionRecord
	head, err := last.Hash()
	if err != nil {
		t.Fatal(err)
	}
	wanted := v3.InventoryChain{Chain: "sha256:" + first, Format: "action_v1", Record: "sha256:" + head}
	if last.ChainSeq <= math.MaxInt64 {
		wanted.Seq = int64(last.ChainSeq)
	} else {
		t.Fatalf("frozen chain sequence is out of range: %d", last.ChainSeq)
	}
	var recipes []v3Recipe
	for _, row := range []struct {
		name, verdict, code string
		edit                func(*v3.InventoryChain)
	}{
		{"legacy-prefix", "VALID PREFIX, END UNPROVEN", "LEGACY_END_UNPROVEN", nil},
		{"legacy-head-mismatch", "INVALID", "LEGACY_CHAIN_HEAD_MISMATCH", func(c *v3.InventoryChain) { c.Record = v3.Digest(nil) }},
		{"legacy-truncated", "INVALID", "LEGACY_CHAIN_TRUNCATED", func(c *v3.InventoryChain) { c.Seq++ }},
		{"legacy-extended", "INVALID", "LEGACY_EXTENDED_AFTER_CUTOVER", func(c *v3.InventoryChain) { c.Seq-- }},
		{"inventory-mismatch", "INVALID", "CUTOVER_INVENTORY_MISMATCH", nil},
		{"inventory-absent", "INCOMPLETE", "CUTOVER_INVENTORY_NOT_PRESENTED", nil},
	} {
		chain := wanted
		if row.edit != nil {
			row.edit(&chain)
		}
		inventory := v3Canonical(t, v3.Inventory{V: 1, Chains: []v3.InventoryChain{chain}})
		digest := v3.Digest(inventory)
		s := v3New(t)
		s.records = nil
		body := v3DefaultOpen(s.key, s.lineage)
		body["legacy_cutover"] = v3Common{"chains": 1, "inventory": digest}
		s.add(t, "stream_open", body, nil)
		files := []v3File{s.finish(t), {legacyName, legacy}}
		if row.name != "inventory-absent" {
			if row.name == "inventory-mismatch" {
				inventory = append(inventory, '\n')
			}
			files = append(files, v3File{v3.InventoryFilename(digest), inventory})
		}
		req := v3Request{Directory: true, Keys: []string{}, AllowUnpinned: true}
		recipes = append(recipes, v3Recipe{group: 9, name: row.name, verdict: row.verdict, code: row.code, request: req, files: files})
	}
	corrupt := chain[0]
	sig, tail := corrupt.Signature[:1], corrupt.Signature[1:]
	replacement := "0"
	if sig == replacement {
		replacement = "1"
	}
	corrupt.Signature = replacement + tail
	entry := entries[0]
	entry.RawDetail, entry.Detail = nil, corrupt
	entry.Hash = recorder.ComputeHash(entry)
	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	inventory := v3Canonical(t, v3.Inventory{V: 1, Chains: []v3.InventoryChain{{
		Chain: wanted.Chain, Format: wanted.Format, Record: "sha256:" + first,
	}}})
	rootWithLegacy := v3New(t)
	rootWithLegacy.records = nil
	open := v3DefaultOpen(rootWithLegacy.key, rootWithLegacy.lineage)
	digest := v3.Digest(inventory)
	open["legacy_cutover"] = v3Common{"chains": 1, "inventory": digest}
	rootWithLegacy.add(t, "stream_open", open, nil)
	recipes = append(recipes, v3Recipe{
		group: 9, name: "legacy-bad-signature", code: "LEGACY_INVALID", verdict: "INVALID",
		request: v3Request{Directory: true, Keys: []string{}, AllowUnpinned: true},
		files:   []v3File{rootWithLegacy.finish(t), {legacyName, append(line, '\n')}, {v3.InventoryFilename(digest), inventory}},
	})
	for _, row := range []struct {
		name, inventory string
	}{
		{"empty-inventory-count", ""},
		{"invalid-inventory-journal", `{"chains":[],"journal":"invalid","v":1}`},
		{"invalid-inventory-version", `{"chains":[],"v":2}`},
		{"inventory-trailing-data", `{"chains":[],"v":1}{}`},
	} {
		stream := v3New(t)
		stream.records = nil
		body := v3DefaultOpen(stream.key, stream.lineage)
		chains, digest := 1, v3.EmptyInventoryDigest()
		if row.inventory != "" {
			chains, digest = 0, v3.Digest([]byte(row.inventory))
		}
		body["legacy_cutover"] = v3Common{"chains": chains, "inventory": digest}
		stream.add(t, "stream_open", body, nil)
		recipe := v3Invalid(9, row.name, "CUTOVER_INVENTORY_MISMATCH", stream.finish(t))
		if row.inventory != "" {
			recipe.files = append(recipe.files, v3File{v3.InventoryFilename(digest), []byte(row.inventory)})
		}
		recipes = append(recipes, recipe)
	}
	// The inventory binds no old chains here. An old chain is either an
	// unlisted chain or has unknown membership when the root is absent.
	root := v3New(t)
	owned := root.finish(t)
	missing := v3Successor(t, root, secondStream, "closed", 1, nil).finish(t)
	for _, row := range []struct {
		name, verdict, code string
		file                v3File
		legacy              []byte
	}{
		{"unlisted-legacy", "INVALID", "LEGACY_CHAIN_UNLISTED", owned, legacy},
		{"unknown-membership", "INCOMPLETE", "LEGACY_MEMBERSHIP_UNKNOWN", missing, legacy},
		{"invalid-legacy", "INVALID", "LEGACY_INVALID", owned, []byte("{\n")},
	} {
		req := v3Request{Directory: true, Keys: []string{}, AllowUnpinned: true}
		name := legacyName
		if row.name == "invalid-legacy" {
			name = "activation-receipts.jsonl"
		}
		recipes = append(recipes, v3Recipe{
			group: 9, name: row.name, verdict: row.verdict, code: row.code, request: req,
			files: []v3File{row.file, {name, row.legacy}},
		})
	}
	bare, err := actionreceipt.Marshal(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, code string
		bytes      []byte
	}{
		{"legacy-object-after-action", "LEGACY_INVALID", slices.Concat(bare, []byte("\n{}\n"))},
		{"legacy-null-after-action", "LEGACY_INVALID", slices.Concat(bare, []byte("\nnull\n"))},
		{"legacy-null-first", "UNRECOGNIZED_FILE", []byte("null\n")},
	} {
		recipes = append(recipes, v3Recipe{
			group: 9, name: row.name, code: row.code, verdict: "INVALID",
			files: []v3File{owned, {"example.jsonl", row.bytes}},
		})
	}
	bareEvidence, err := os.ReadFile("testdata/secret-egress-v1/valid-raw-unrewritable-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := slices.Concat([]byte(`{"type":"evidence_receipt","detail":`), bytes.TrimSpace(bareEvidence), []byte("}\n"))
	recipes = append(recipes, v3Recipe{
		group: 9, name: "legacy-bare-evidence-under-run-name", code: "LEGACY_CHAIN_UNLISTED", verdict: "INVALID",
		request: v3Request{Directory: true, Keys: append(v3LegacyRequest(t, "valid-raw-unrewritable-intent.json", bareEvidence).Keys, hex.EncodeToString(v3Public(root.key)))},
		files:   []v3File{owned, {"evidence-example.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0.jsonl", wrapper}},
	})
	recipes = append(recipes, v3RotatedCutoverRecipes(t)...)
	return append(recipes, v3LegacyForkRecipes(t)...)
}

// v3LegacyForkRecipes presents two signed action chains that share their first
// record and disagree at the second. Each chain verifies alone, so only the
// fork can break them. A forked chain is broken whether or not a cutover
// stream binds it, and a bound fork never matches its pinned head.
func v3LegacyForkRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	key := v3Key("legacy fork")
	signer := hex.EncodeToString(v3Public(key))
	sign := func(action string, seq uint64, prev string) (actionreceipt.Receipt, string, string) {
		record := actionreceipt.ActionRecord{
			Version: actionreceipt.ActionRecordVersion, ActionID: action, ActionType: actionreceipt.ActionRead,
			Timestamp: time.Date(2026, 1, 1, 0, 0, int(seq), 0, time.UTC),
			Target:    "api.vendor.example", Transport: "fetch", Verdict: "allow",
			ChainPrevHash: prev, ChainSeq: seq,
		}
		signed, err := actionreceipt.Sign(record, key)
		if err != nil {
			t.Fatal(err)
		}
		head, err := record.Hash()
		if err != nil {
			t.Fatal(err)
		}
		link, err := actionreceipt.ReceiptHash(signed)
		if err != nil {
			t.Fatal(err)
		}
		return signed, "sha256:" + head, link
	}
	genesis, first, link := sign("example-fork-0", 0, actionreceipt.GenesisHash)
	var files [2][]byte
	var heads [2]string
	for i, action := range []string{"example-fork-a", "example-fork-b"} {
		second, head, _ := sign(action, 1, link)
		for _, receipt := range []actionreceipt.Receipt{genesis, second} {
			line, err := actionreceipt.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			files[i] = append(files[i], line...)
			files[i] = append(files[i], '\n')
		}
		heads[i] = head
	}
	chains := []v3File{{"activation-receipts.jsonl", files[0]}, {"redaction-receipts.jsonl", files[1]}}
	root := v3New(t)
	bound := v3New(t)
	bound.records = nil
	inventory := v3Canonical(t, v3.Inventory{V: 1, Chains: []v3.InventoryChain{{Chain: first, Format: "action_v1", Record: heads[0], Seq: 1}}})
	digest := v3.Digest(inventory)
	open := v3DefaultOpen(bound.key, bound.lineage)
	open["legacy_cutover"] = v3Common{"chains": 1, "inventory": digest}
	bound.add(t, "stream_open", open, nil)
	missing := v3Successor(t, root, secondStream, "closed", 1, nil).finish(t)
	return []v3Recipe{{
		group: 9, name: "legacy-fork-unknown-membership", verdict: "INCOMPLETE", code: "LEGACY_MEMBERSHIP_UNKNOWN",
		request: v3Request{Directory: true, Keys: []string{signer, hex.EncodeToString(v3Public(root.key))}},
		files:   append([]v3File{missing}, chains...),
	}, {
		group: 9, name: "legacy-fork-unbound", verdict: "INVALID", code: "LEGACY_CHAIN_UNLISTED",
		request: v3Request{Directory: true, Keys: []string{signer, hex.EncodeToString(v3Public(root.key))}},
		files:   append([]v3File{root.finish(t)}, chains...),
	}, {
		group: 9, name: "legacy-fork-bound", verdict: "INVALID", code: "LEGACY_CHAIN_HEAD_MISMATCH",
		request: v3Request{Directory: true, AllowPrefix: true, Keys: []string{signer, hex.EncodeToString(v3Public(bound.key))}},
		files:   append([]v3File{bound.finish(t), {v3.InventoryFilename(digest), inventory}}, chains...),
	}}
}

func v3RotatedCutoverRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	before, after := v3Key("rotation prior"), v3Key("rotation successor")
	priorSigner := hex.EncodeToString(v3Public(before))
	const priorCount = 3
	var legacy bytes.Buffer
	var heads [priorCount + 2]string
	var sequences [len(heads)]int64
	var chain []actionreceipt.Receipt
	var unrotatedBytes, prefixBytes, rotationBytes int
	prev := actionreceipt.GenesisHash
	for i := range heads {
		key, seq := before, uint64(i)
		sequences[i] = int64(i)
		var transition *actionreceipt.KeyTransition
		if i >= priorCount {
			key, seq = after, uint64(i-priorCount)
			sequences[i] = int64(i - priorCount)
		}
		if i == priorCount-1 {
			unrotatedBytes = legacy.Len()
		}
		if i == len(heads)-1 {
			prefixBytes = legacy.Len()
		}
		if i == priorCount {
			rotationBytes = legacy.Len()
			transition = &actionreceipt.KeyTransition{PriorSignerKey: priorSigner, PriorChainSeq: priorCount - 1, PriorChainHash: prev}
		}
		record := actionreceipt.ActionRecord{
			Version: actionreceipt.ActionRecordVersion, ActionID: fmt.Sprintf("example-%d", i), ActionType: actionreceipt.ActionRead,
			Timestamp: time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC),
			Target:    "api.vendor.example", Transport: "fetch", Verdict: "allow",
			ChainPrevHash: prev, ChainSeq: seq, KeyTransition: transition,
		}
		signed, err := actionreceipt.Sign(record, key)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, signed)
		line, err := actionreceipt.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		legacy.Write(line)
		legacy.WriteByte('\n')
		head, err := record.Hash()
		if err != nil {
			t.Fatal(err)
		}
		heads[i] = "sha256:" + head
		prev, err = actionreceipt.ReceiptHash(signed)
		if err != nil {
			t.Fatal(err)
		}
	}
	keys := []string{priorSigner, hex.EncodeToString(v3Public(after))}
	if result := actionreceipt.VerifyChainTrusted(chain, keys); !result.Valid {
		t.Fatalf("rotation receipt recipe is invalid: %s", result.Error)
	}
	var recipes []v3Recipe
	for _, tc := range []struct {
		name          string
		pin           int
		presented     []byte
		verdict, code string
	}{
		{"unrotated-truncation", priorCount - 1, legacy.Bytes()[:unrotatedBytes], "INVALID", "LEGACY_CHAIN_TRUNCATED"},
		{"rotation-match", len(heads) - 1, legacy.Bytes(), "VALID PREFIX, END UNPROVEN", "LEGACY_END_UNPROVEN"},
		{"rotation-extension", priorCount - 1, legacy.Bytes(), "INVALID", "LEGACY_EXTENDED_AFTER_CUTOVER"},
		{"rotation-truncation", len(heads) - 1, legacy.Bytes()[:prefixBytes], "INVALID", "LEGACY_CHAIN_HEAD_MISMATCH"},
		{"rotation-boundary-truncation", priorCount, legacy.Bytes()[:rotationBytes], "INVALID", "LEGACY_CHAIN_HEAD_MISMATCH"},
		{"rotation-later-pin-absent", len(heads) - 1, legacy.Bytes()[:rotationBytes], "INVALID", "LEGACY_CHAIN_HEAD_MISMATCH"},
	} {
		s := v3New(t)
		s.records = nil
		inventory := v3Canonical(t, v3.Inventory{V: 1, Chains: []v3.InventoryChain{{
			Chain: heads[0], Format: "action_v1", Record: heads[tc.pin], Seq: sequences[tc.pin],
		}}})
		digest := v3.Digest(inventory)
		open := v3DefaultOpen(s.key, s.lineage)
		open["legacy_cutover"] = v3Common{"chains": 1, "inventory": digest}
		s.add(t, "stream_open", open, nil)
		recipes = append(recipes, v3Recipe{
			group: 9, name: tc.name, verdict: tc.verdict, code: tc.code,
			request: v3Request{Directory: true, AllowPrefix: true, Keys: []string{
				priorSigner, hex.EncodeToString(v3Public(after)), hex.EncodeToString(v3Public(s.key)),
			}},
			files: []v3File{s.finish(t), {"activation-receipts.jsonl", tc.presented}, {v3.InventoryFilename(digest), inventory}},
		})
	}
	return recipes
}

func v3OperationalEntry(t *testing.T) []byte {
	t.Helper()
	entry := recorder.Entry{
		Version: 1, Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), SessionID: "example", Type: "decision", Transport: "mcp",
		Summary: "example", PrevHash: recorder.GenesisHash,
		Detail: json.RawMessage("{}"), RawDetail: json.RawMessage("{}"),
	}
	entry.Hash = recorder.ComputeHash(entry)
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func v3OperationalOnlyRecipe(t *testing.T) v3Recipe {
	t.Helper()
	return v3Recipe{
		group: 7, name: "operational-logs-only", verdict: "INCOMPLETE", code: "NO_EVIDENCE",
		request: v3Request{Directory: true},
		files:   []v3File{{"evidence-example-0.jsonl", v3OperationalEntry(t)}},
	}
}

// An operational recorder file that carries no receipts is ignored beside
// verified v3 evidence, not reported as unrecognized.
func v3OperationalRecorderFileRecipe(t *testing.T) v3Recipe {
	t.Helper()
	root := v3New(t)
	return v3Recipe{
		group: 7, name: "operational-recorder-file-ignored", verdict: "VALID",
		request: v3Request{Directory: true, Keys: []string{hex.EncodeToString(v3Public(root.key))}},
		files:   []v3File{root.finish(t), {"activation-receipts.jsonl", v3OperationalEntry(t)}},
	}
}
