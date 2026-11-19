// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func v3BodyRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	var recipes []v3Recipe
	base := v3New(t)
	for _, family := range []struct {
		kind string
		body v3Common
	}{
		{"stream_open", v3DefaultOpen(base.key, base.lineage)},
		{"stream_close", v3Close(1)},
		{"heartbeat", v3Heartbeat()},
		{"action", v3DefaultAction()},
	} {
		names := make([]string, 0, len(family.body))
		for field := range family.body {
			names = append(names, field)
		}
		slices.Sort(names)
		for _, field := range names {
			s := v3New(t)
			body := v3Common{}
			for k, v := range family.body {
				if k != field {
					body[k] = v
				}
			}
			if family.kind == "stream_open" {
				s.records = nil
				if field == "signer_key" {
					// The pin supplies the key so this case reaches body validation.
					body["policy"] = family.body["policy"]
				}
			}
			s.add(t, family.kind, body, nil)
			if family.kind != "stream_close" {
				s.close(t)
			}
			recipes = append(recipes, v3Invalid(6, family.kind+"-missing-"+field, "BODY_SCHEMA", s.file(0, len(s.records))))
		}
	}
	for _, row := range []struct {
		name   string
		fields v3Common
	}{
		{"caller-none-has-identity", v3Common{"caller": v3Common{"authn": "none", "client_id": "example"}}},
		{"caller-verified-missing-identity", v3Common{"caller": v3Common{"authn": "mcp_door_verified", "client_id": "example"}}},
		{"action-writer-config", v3Common{"policy": v3Common{"source": "writer_config", "hash": v3.Digest(nil)}}},
		{"unavailable-policy-with-hash", v3Common{"policy": v3Common{"source": "unavailable", "hash": v3.Digest(nil)}}},
		{"snapshot-policy-without-hash", v3Common{"policy": v3Common{"source": "request_snapshot"}}},
		{"unavailable-checker", v3Common{"checker": v3Common{"surface": "scan_api", "mode": "off", "selection": "unavailable", "disposition": "passed"}}},
		{"configured-checker-no-hash", v3Common{"checker": v3Common{"surface": "scan_api", "mode": "block", "selection": "configured", "disposition": "passed"}}},
		{"ask-observation", v3Common{
			"verdict": "ask", "effect_boundary": "hook_execution", "effect_relation": "before",
			"ask": v3Common{"channel": "host_prompt", "observed": true},
		}},
		{"verdict-payload-hash", v3Common{"checker": v3Common{
			"surface": "scan_api", "mode": "block", "selection": "configured", "disposition": "passed",
			"config_hash": v3.Digest(nil), "verdict_payload_hash": v3.Digest(nil),
		}}},
		{"data-derived-field", v3Common{"data": v3Common{"reversibility": "unknown", "side_effect_class": "unknown", "unknown_label": "value"}}},
	} {
		s := v3New(t)
		body := v3DefaultAction()
		for k, v := range row.fields {
			body[k] = v
		}
		s.add(t, "action", body, nil)
		recipes = append(recipes, v3Invalid(6, row.name, "BODY_SCHEMA", s.finish(t)))
	}
	for _, row := range []struct {
		field  string
		change v3Common
	}{
		{"action-type", v3Common{"action_type": "future"}},
		{"authn", v3Common{"caller": v3Common{"authn": "future"}}},
		{"boundary", v3Common{"effect_boundary": "future"}},
		{"relation", v3Common{"effect_relation": "future"}},
		{"phase", v3Common{"phase": "future"}},
		{"policy-source", v3Common{"policy": v3Common{"source": "future"}}},
		{"verdict", v3Common{"verdict": "future"}},
		{"outcome", v3Common{"phase": "outcome", "attempt": 1, "outcome_class": "future", "effect_boundary": "upstream_send", "effect_relation": "after", "verdict": "allow"}},
		{"ask-channel", v3Common{"verdict": "ask", "effect_boundary": "hook_execution", "effect_relation": "before", "ask": v3Common{"channel": "future", "observed": false}}},
	} {
		s := v3New(t)
		body := v3DefaultAction()
		for k, v := range row.change {
			body[k] = v
		}
		s.add(t, "action", body, nil)
		recipes = append(recipes, v3Recipe{group: 6, name: "unknown-" + row.field, code: "ACTION_UNINTERPRETED", verdict: "INCOMPLETE", files: []v3File{s.finish(t)}})
	}
	for _, field := range []string{"surface", "selection", "mode", "disposition"} {
		s := v3New(t)
		body := v3DefaultAction()
		checker := v3Common{"surface": "scan_api", "mode": "block", "selection": "configured", "disposition": "passed", "config_hash": v3.Digest(nil)}
		checker[field] = "future"
		body["checker"] = checker
		s.add(t, "action", body, nil)
		recipes = append(recipes, v3Recipe{group: 6, name: "unknown-checker-" + field, code: "ACTION_UNINTERPRETED", verdict: "INCOMPLETE", files: []v3File{s.finish(t)}})
	}
	s := v3New(t)
	s.add(t, "action", v3DefaultAction(), nil)
	s.add(t, "heartbeat", v3Heartbeat(), nil)
	recipes = append(recipes, v3Recipe{group: 6, name: "known-bodies", verdict: "VALID", files: []v3File{s.finish(t)}})
	s = v3New(t)
	s.add(t, "heartbeat", v3Common{}, func(m v3Common) { m["body_v"] = 2 })
	s.add(t, "future_event", v3Common{}, nil)
	recipes = append(recipes, v3Recipe{group: 6, name: "unknown-event", code: "EVENT_UNINTERPRETED", verdict: "VALID", files: []v3File{s.finish(t)}})
	s = v3New(t)
	s.add(t, "action", v3Common{}, func(m v3Common) { m["body_v"] = 2 })
	recipes = append(recipes, v3Recipe{group: 6, name: "higher-action", code: "DECISIONS_NOT_APPRAISED", verdict: "INCOMPLETE", files: []v3File{s.finish(t)}})
	for _, name := range []string{"higher-close", "unknown-close-reason", "unknown-open-policy", "unknown-signer-algorithm"} {
		s := v3New(t)
		switch name {
		case "higher-close":
			s.add(t, "stream_close", v3Close(1), func(m v3Common) { m["body_v"] = 2 })
		case "unknown-close-reason":
			body := v3Close(1)
			body["reason"] = "future"
			s.add(t, "stream_close", body, nil)
		default:
			s.records = nil
			body := v3DefaultOpen(s.key, s.lineage)
			if name == "unknown-open-policy" {
				body["policy"].(v3Common)["source"] = "future"
			} else {
				body["signer_key"].(v3Common)["alg"] = "future"
			}
			s.add(t, "stream_open", body, nil)
			s.close(t)
		}
		recipes = append(recipes, v3Recipe{group: 6, name: name, code: "UNKNOWN_CONTROL", verdict: "UNSUPPORTED", files: []v3File{s.file(0, len(s.records))}})
	}
	s = v3New(t)
	s.add(t, "heartbeat", v3Heartbeat(), func(m v3Common) { m["crit"] = []string{"future"} })
	recipes = append(recipes, v3Recipe{group: 6, name: "unknown-critical-feature", code: "UNKNOWN_CRIT", verdict: "UNSUPPORTED", files: []v3File{s.finish(t)}})
	s = v3New(t)
	badCriticalAction := v3DefaultAction()
	badCriticalAction["action_id"] = 1
	s.add(t, "action", badCriticalAction, func(m v3Common) { m["crit"] = []string{"future"} })
	recipes = append(recipes, v3Recipe{group: 6, name: "unknown-critical-action", code: "UNKNOWN_CRIT", verdict: "UNSUPPORTED", files: []v3File{s.finish(t)}})
	s = v3New(t)
	body := v3DefaultAction()
	body["normalization"] = v3Common{"id": "example", "digest": v3.Digest(nil)}
	s.add(t, "action", body, nil)
	recipes = append(recipes, v3Recipe{group: 6, name: "unknown-normalization-profile", code: "NORMALIZATION_UNKNOWN", verdict: "VALID", files: []v3File{s.finish(t)}})

	return append(append(recipes, v3NestedBodyRecipes(t)...), v3ByteLimitRecipes(t)...)
}

func v3ByteLimitRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	var recipes []v3Recipe
	for _, tc := range []struct {
		name, unit string
		count      int
	}{
		{"target-exact-bytes", "a", 2048},
		{"target-excess-bytes", "é", 1025},
		{"writer-exact-bytes", "a", 128},
		{"writer-excess-bytes", "é", 65},
	} {
		s := v3New(t)
		value := strings.Repeat(tc.unit, tc.count)
		if strings.HasPrefix(tc.name, "target") {
			action := v3DefaultAction()
			action["target"] = value
			s.add(t, "action", action, nil)
		} else {
			s.records = nil
			body := v3DefaultOpen(s.key, s.lineage)
			body["writer"].(v3Common)["instance"] = value
			s.add(t, "stream_open", body, nil)
		}
		file := s.finish(t)
		if strings.Contains(tc.name, "excess") {
			recipes = append(recipes, v3Invalid(6, tc.name, "BODY_SCHEMA", file))
		} else {
			recipes = append(recipes, v3Recipe{group: 6, name: tc.name, verdict: "VALID", files: []v3File{file}})
		}
	}
	return recipes
}

func v3TrustRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	s := v3New(t)
	valid := s.finish(t)
	changed := v3New(t)
	changed.key = v3Key("other")
	changed.close(t)
	other := &v3Stream{id: strings.Repeat("3", 32), lineage: strings.Repeat("4", 32), key: changed.key}
	other.add(t, "stream_open", v3DefaultOpen(other.key, other.lineage), nil)
	return []v3Recipe{
		{
			group: 8, name: "unannounced-key-change", code: "STREAM_ORDER", verdict: "INVALID",
			request: v3Request{Keys: []string{}}, files: []v3File{changed.file(0, 2), other.finish(t)},
		},
		{group: 8, name: "pinned", verdict: "VALID", files: []v3File{valid}},
		{group: 8, name: "wrong-pin", verdict: "INVALID", code: "TRUST", request: v3Request{Keys: []string{hex.EncodeToString(v3Public(v3Key("other")))}}, files: []v3File{valid}},
		{group: 8, name: "unpinned-refused", verdict: "SELF-CONSISTENT ONLY", request: v3Request{Keys: []string{}}, files: []v3File{valid}},
		{group: 8, name: "unpinned-allowed", verdict: "SELF-CONSISTENT ONLY", request: v3Request{AllowUnpinned: true, Keys: []string{}}, files: []v3File{valid}},
	}
}

func v3SpecialRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	s := v3New(t)
	valid := s.finish(t)
	first := v3New(t)
	first.add(t, "heartbeat", v3Heartbeat(), nil)
	left := first.finish(t)
	second := v3New(t)
	second.add(t, "action", v3DefaultAction(), nil)
	right := second.finish(t)
	right.name = "copy/" + right.name
	alternate := v3New(t)
	alternate.records = nil
	alternateOpen := v3DefaultOpen(alternate.key, alternate.lineage)
	alternateOpen["writer"].(v3Common)["instance"] = "another instance"
	alternate.add(t, "stream_open", alternateOpen, nil)
	forkedOpen := alternate.finish(t)
	forkedOpen.name = "copy/" + forkedOpen.name
	recipes := []v3Recipe{
		{group: 12, name: "contested-opener-order", verdict: "INVALID", code: "FORK", files: []v3File{valid, forkedOpen}},
		{group: 11, name: "dsse-export", verdict: "VALID", files: []v3File{valid}},
		{group: 12, name: "fork-order", verdict: "INVALID", code: "FORK", files: []v3File{left, right}},
		{group: 12, name: "duplicate-order", verdict: "VALID", files: []v3File{valid, {"copy/" + valid.name, valid.bytes}}},
	}
	nonOpen := v3New(t)
	nonOpen.records = nil
	nonOpen.add(t, "action", v3DefaultAction(), nil)
	contender := nonOpen.file(0, 1)
	contender.name = "copy/" + contender.name
	recipes = append(recipes, v3Recipe{
		group: 12, name: "contested-non-opener", verdict: "INVALID", code: "FORK",
		files: []v3File{valid, contender},
	})
	broken := v3New(t)
	broken.add(t, "heartbeat", v3Common{"beat": 1}, func(p v3Common) { p["prev"] = v3.Digest(nil) })
	broken.close(t)
	recipes = append(recipes, v3Recipe{
		group: 12, name: "predecessor-before-body", verdict: "INVALID", code: "STREAM_ORDER",
		files: []v3File{broken.file(0, 1), broken.file(1, 3)},
	})

	damaged := broken.file(0, 1)
	damaged.name = "copy/" + damaged.name
	damaged.bytes = []byte("{}\n")
	emptyInventory := v3Canonical(t, v3.Inventory{V: 1, Chains: []v3.InventoryChain{}})
	emptyName := v3.InventoryFilename(v3.EmptyInventoryDigest())
	damagedInventory := append(bytes.Clone(emptyInventory), '\n')
	recipes = append(recipes,
		v3Recipe{group: 12, name: "damaged-copy-order", code: "STREAM_ORDER", verdict: "INVALID", extraInvalid: []string{"LINE_LAYOUT"}, files: []v3File{broken.file(0, 1), broken.file(1, 3), damaged}},
		v3Recipe{
			group: 12, name: "damaged-inventory-first", code: "CUTOVER_INVENTORY_MISMATCH", verdict: "INVALID",
			files: []v3File{valid, {"a/" + emptyName, damagedInventory}, {"b/" + emptyName, emptyInventory}},
		},
		v3Recipe{
			group: 12, name: "damaged-inventory-last", code: "CUTOVER_INVENTORY_MISMATCH", verdict: "INVALID",
			files: []v3File{valid, {"a/" + emptyName, emptyInventory}, {"b/" + emptyName, damagedInventory}},
		},
		v3Recipe{
			group: 12, name: "damaged-unpinned-inventory", code: "CUTOVER_INVENTORY_MISMATCH", verdict: "INVALID",
			files: []v3File{valid, {v3.InventoryFilename(v3.Digest(nil)), damagedInventory}},
		},
	)

	afterClose := v3New(t)
	afterClose.close(t)
	afterClose.add(t, "heartbeat", v3Common{"beat": 1}, nil)
	recipes = append(recipes, v3Recipe{
		group: 12, name: "close-before-body", verdict: "INVALID", code: "DATA_AFTER_CLOSE",
		files: []v3File{afterClose.file(0, 2), afterClose.file(2, 3)},
	})
	critical := &v3Stream{id: s.id, lineage: s.lineage, key: v3Key("other")}
	critical.add(t, "stream_open", v3DefaultOpen(critical.key, critical.lineage), func(p v3Common) {
		p["crit"] = []string{"future"}
	})
	recipes = append(recipes, v3Recipe{
		group: 8, name: "body-before-trust", verdict: "UNSUPPORTED", code: "UNKNOWN_CRIT",
		files: []v3File{critical.file(0, 1)},
	})

	const chains = 1025
	rows := make([]v3.InventoryChain, 0, chains)
	for i := range chains {
		rows = append(rows, v3.InventoryChain{Format: "action_v1", Chain: fmt.Sprintf("%032x", i), Seq: 0, Record: v3.Digest(nil)})
	}
	inventory := v3Canonical(t, v3.Inventory{V: 1, Chains: rows})
	root := v3New(t)
	root.records = nil
	body := v3DefaultOpen(root.key, root.lineage)
	digest := v3.Digest(inventory)
	body["legacy_cutover"] = v3Common{"inventory": digest, "chains": chains}
	root.add(t, "stream_open", body, nil)
	recipes = append(recipes, v3Recipe{
		group: 9, name: "inventory-over-1024-chains", verdict: "INCOMPLETE", code: "LEGACY_CHAIN_NOT_PRESENTED",
		files: []v3File{root.finish(t), {v3.InventoryFilename(digest), inventory}},
	})
	for _, source := range []string{
		"frozen/v1/action-receipt-v1-chain.jsonl",
		"frozen/v1/action-receipt-v1-single.json",
		"frozen/v1/aarp-v0.1-envelope.aarp.json",
		"secret-egress-v1/valid-transformed-intent.json",
		"secret-egress-v1/valid-raw-unrewritable-intent.json",
	} {
		name := filepath.Base(source)
		data, err := os.ReadFile(filepath.Clean(filepath.Join("testdata", source)))
		if err != nil {
			t.Fatal(err)
		}
		recipes = append(recipes, v3Recipe{
			group: 10, name: strings.TrimSuffix(name, filepath.Ext(name)),
			request: v3LegacyRequest(t, name, data), files: []v3File{{name, data}},
		})
	}
	return recipes
}

func v3CheckSpecial(t *testing.T, recipe v3Recipe, paths []string, opts v3.Options, full []byte) []v3File {
	t.Helper()
	switch recipe.group {
	case 11:
		var exported bytes.Buffer
		for first := range bytes.SplitSeq(recipe.files[0].bytes, []byte{'\n'}) {
			if len(first) == 0 {
				continue
			}
			line := append(bytes.Clone(first), '\n')
			envelope, code := v3.ExportDSSE(line)
			if code != "" {
				t.Fatal(code)
			}
			exported.Write(envelope)
			exported.WriteByte('\n')
			var dsse struct {
				Payload     string
				PayloadType string
				Signatures  []struct{ Sig string }
			}
			if err := json.Unmarshal(envelope, &dsse); err != nil {
				t.Fatal(err)
			}
			payload, err := base64.StdEncoding.DecodeString(dsse.Payload)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := base64.StdEncoding.DecodeString(dsse.Signatures[0].Sig)
			if err != nil {
				t.Fatal(err)
			}
			if dsse.PayloadType != v3.PayloadType || !ed25519.Verify(v3Public(v3Key("first")), fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(dsse.PayloadType), dsse.PayloadType, len(payload), payload), sig) {
				t.Fatal("DSSE signature mismatch")
			}
		}
		return []v3File{{"export.dsse.jsonl", exported.Bytes()}}
	case 12:
		if recipe.name == "damaged-copy-order" {
			v3CheckDamagedCopy(t, paths, opts, full)
		}
		slices.Reverse(paths)
		result, err := v3.VerifyPaths(t.Context(), paths, opts)
		if err != nil {
			t.Fatal(err)
		}
		data, err := result.JSON()
		if err != nil || !bytes.Equal(data, full) {
			t.Fatalf("result changed with file order: %v", err)
		}
	}
	return nil
}

func v3CheckDamagedCopy(t *testing.T, paths []string, opts v3.Options, withDamage []byte) {
	t.Helper()
	var damaged v3.Result
	if err := json.Unmarshal(withDamage, &damaged); err != nil {
		t.Fatal(err)
	}
	damaged.Findings = slices.DeleteFunc(damaged.Findings, func(f v3.Finding) bool {
		return f.Code == "LINE_LAYOUT" && f.Seq == nil
	})
	filtered, err := damaged.JSON()
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := v3.VerifyPaths(t.Context(), paths[:len(paths)-1], opts)
	if err != nil {
		t.Fatal(err)
	}
	original, err := baseline.JSON()
	if err != nil || !bytes.Equal(original, filtered) {
		t.Fatalf("damaged copy changed the original result after excluding the damage: %v\n%s\n%s", err, original, filtered)
	}
}

func v3LegacyRequest(t *testing.T, name string, data []byte) v3Request {
	t.Helper()
	request := v3Request{Legacy: true}
	if strings.HasSuffix(name, ".aarp.json") {
		signer, _ := keyFromSeed(seedSigner)
		issuer, _ := keyFromSeed(seedIssuer)
		request.Keys = []string{}
		request.AARPTrust = &v3AARPTrust{
			Keys:      map[string]string{keyIDSigner: hex.EncodeToString(signer), keyIDIssuer: hex.EncodeToString(issuer)},
			Mediators: map[string]v3AARPAuthority{keyIDSigner: {MediatorID: mediatorID, Role: roleMediator}},
		}
		return request
	}
	request.Keys = v3LegacyKeys(t, name, data)
	return request
}

func v3LegacyKeys(t *testing.T, name string, data []byte) []string {
	t.Helper()
	if strings.HasSuffix(name, ".jsonl") {
		line, _, _ := bytes.Cut(data, []byte{'\n'})
		var record struct {
			Detail struct {
				SignerKey string `json:"signer_key"`
			}
		}
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		return []string{record.Detail.SignerKey}
	}
	if strings.HasPrefix(name, "action-receipt-v1") {
		receipt, err := actionreceipt.Unmarshal(data)
		if err != nil {
			t.Fatal(err)
		}
		return []string{receipt.SignerKey}
	}
	receipt, err := contractreceipt.ParseEvidenceReceipt(data)
	if err != nil {
		t.Fatal(err)
	}
	return []string{receipt.Signature.SignerKeyID}
}

func v3CheckLegacy(t *testing.T, file v3File, request v3Request) {
	t.Helper()
	keys := request.Keys
	switch {
	case strings.HasSuffix(file.name, ".aarp.json"):
		envelope, err := aarp.Unmarshal(file.bytes)
		if err != nil {
			t.Fatal(err)
		}
		if request.AARPTrust == nil {
			t.Fatal("legacy envelope request lacks trust inputs")
		}
		opts := aarp.VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{}, Trust: map[string]aarp.TrustEntry{}}
		for id, encoded := range request.AARPTrust.Keys {
			key, err := v3.DecodeKeys([]string{encoded})
			if err != nil {
				t.Fatal(err)
			}
			opts.TrustedKeys[id] = key[0]
		}
		for id, binding := range request.AARPTrust.Mediators {
			opts.Trust[id] = aarp.TrustEntry{MediatorID: binding.MediatorID, Role: binding.Role}
		}
		result, err := aarp.Verify(envelope, opts)
		if err != nil || !result.AssertionSigned || !slices.Contains(result.VerifiedClaims, aarp.ClaimMediatorKeyPinned) {
			t.Fatalf("legacy envelope verification: %v", err)
		}
	case strings.HasSuffix(file.name, ".jsonl"):
		entries, err := recorder.ReadHistoryEntriesFromReader(bytes.NewReader(file.bytes))
		if err != nil {
			t.Fatal(err)
		}
		receipts, _, found, err := actionreceipt.RecorderFileChains("evidence-conformance-session-0.jsonl", entries)
		if err != nil || !found {
			t.Fatalf("read frozen receipt chain: %v", err)
		}
		if result := actionreceipt.VerifyChainTrusted(receipts, keys); !result.Valid {
			t.Fatal(result.Error)
		}
	case strings.HasPrefix(file.name, "action-receipt-v1"):
		receipt, err := actionreceipt.Unmarshal(file.bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := actionreceipt.VerifyInternalConsistencyOnly(receipt); err != nil {
			t.Fatal(err)
		}
	default:
		receipt, err := contractreceipt.ParseEvidenceReceipt(file.bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := actionreceipt.VerifyEvidenceReceipt(receipt, keys[0]); err != nil {
			t.Fatal(err)
		}
	}
}
