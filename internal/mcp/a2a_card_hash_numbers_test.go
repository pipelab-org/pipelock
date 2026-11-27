// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Two cards that differ only in an integer above 2^53 must not share a
// digest: float64 decoding rounded both to the same value, so a change to
// such a field passed drift detection.
func TestHashAgentCard_DistinguishesIntegersAbove2Pow53(t *testing.T) {
	card := func(schema string) A2AAgentCard {
		return A2AAgentCard{
			Name:   "agent",
			URL:    "https://agent.vendor.example/a2a",
			Skills: []A2ASkill{{ID: "lookup", Name: "Lookup", InputSchema: json.RawMessage(schema)}},
		}
	}
	for name, pair := range map[string][2]string{
		"just above 2^53": {`{"maximum":9007199254740993}`, `{"maximum":9007199254740992}`},
		"far above 2^53":  {`{"limit":123456789012345678901234567890}`, `{"limit":123456789012345678901234567891}`},
		"nested in array": {`{"enum":[1,18446744073709551617]}`, `{"enum":[1,18446744073709551616]}`},
	} {
		t.Run(name, func(t *testing.T) {
			if HashAgentCard(card(pair[0])) == HashAgentCard(card(pair[1])) {
				t.Fatalf("cards differing only in %s vs %s share a digest", pair[0], pair[1])
			}
			if cardStructuralDigest(card(pair[0])) == cardStructuralDigest(card(pair[1])) {
				t.Fatalf("structural digest cannot see %s vs %s", pair[0], pair[1])
			}
		})
	}
}

// Integers up to 2^53 and every non-integer number keep the canonical form
// they always had. Only integer literals above 2^53 change: float64 spelling
// rounded or re-spelled them (2^60 printed as 1152921504606847000).
func TestCanonicalizeJSON_KeepsFloatSpellingForRepresentableNumbers(t *testing.T) {
	legacy := func(raw string) []byte {
		var v interface{}
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return []byte(raw)
		}
		out, err := json.Marshal(v)
		if err != nil {
			return []byte(raw)
		}
		return out
	}
	for _, raw := range []string{
		`{"a":1,"b":-0,"c":0}`,
		`{"a":1.0,"b":1.50,"c":1e2,"d":1E-7,"e":-2.5e+3}`,
		`{"exact":9007199254740992,"negative":-9007199254740992}`,
		`[0.1,0.2,123456.789,-1,"x",true,null,{"z":1,"a":[2,3]}]`,
		`{"html":"<a&b>","nested":{"k":[1.25,{"m":7}]}}`,
		`not json`,
		`{"a":1} trailing`,
		`{"a":1e400}`,
	} {
		if got, want := canonicalizeJSON(json.RawMessage(raw)), legacy(raw); !bytes.Equal(got, want) {
			t.Errorf("canonicalizeJSON(%s) = %s, want legacy %s", raw, got, want)
		}
	}
}

// Through the drift scanner itself: an agent card whose only change is an
// integer above 2^53 in a skill schema is a structural change and blocks.
func TestScanAgentCard_BlocksDriftInIntegerAbove2Pow53(t *testing.T) {
	cardBody := func(limit string) []byte {
		return []byte(`{"name":"agent","url":"https://agent.vendor.example/a2a","version":"1",` +
			`"skills":[{"id":"lookup","name":"Lookup","inputSchema":{"type":"integer","maximum":` + limit + `}}]}`)
	}
	cfg := enabledA2ACfg()
	cfg.ScanAgentCards = false // isolate the drift discriminator
	cfg.DetectCardDrift = true
	cfg.Action = config.ActionBlock
	baseline := NewCardBaseline(10)
	key := CardCacheKeyFromRequest("https://agent.vendor.example/.well-known/agent-card.json", "")

	seed := ScanAgentCard(context.Background(), cardBody("9007199254740993"), testA2AScanner(t), baseline, key, cfg)
	if !seed.Clean || !seed.FirstSeen {
		t.Fatalf("seed baseline = clean:%v firstSeen:%v, want clean first-seen", seed.Clean, seed.FirstSeen)
	}
	same := ScanAgentCard(context.Background(), cardBody("9007199254740993"), testA2AScanner(t), baseline, key, cfg)
	if !same.Clean {
		t.Fatalf("unchanged card blocked: %q", same.Reason)
	}
	got := ScanAgentCard(context.Background(), cardBody("9007199254740992"), testA2AScanner(t), baseline, key, cfg)
	if got.Clean || !strings.Contains(got.Reason, "endpoint or structural change") {
		t.Fatalf("large-integer change = clean:%v reason:%q, want structural drift block", got.Clean, got.Reason)
	}
}
