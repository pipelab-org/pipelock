// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"math"
	"os"
	"testing"

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
	independent := &v3Stream{id: secondStream, lineage: root.lineage, key: root.key}
	independent.add(t, "stream_open", v3DefaultOpen(root.key, root.lineage), nil)
	fork := independent.finish(t)
	edited := func(end string, seq int, edit func(v3Common)) v3File {
		return v3Successor(t, root, secondStream, end, seq, edit).finish(t)
	}
	return []v3Recipe{
		{group: 4, name: "pinned-close", verdict: "VALID", files: []v3File{rootFile, secondFile}},
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
	return recipes
}
