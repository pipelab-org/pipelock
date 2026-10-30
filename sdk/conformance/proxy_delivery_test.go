// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestProxyDeliveryOutcomeFixtures(t *testing.T) {
	path := filepath.Join(testdataDir, "proxy-delivery-outcomes.json")
	type vector struct {
		Name    string          `json:"name"`
		Receipt receipt.Receipt `json:"receipt"`
	}
	// Expected observations are fixed here, not read back from the fixture,
	// so a validly re-signed fixture with changed outcome fields fails.
	want := []struct{ name, phase, verdict, pattern string }{
		{"legacy completion", "outcome", "allow", "status=200 bytes=16 reason=complete"},
		{"admission without outcome", "intent", "allow", ""},
		{"delivered representation", "outcome", "allow", "status=200 bytes=16 reason=complete delivered_bytes=130"},
		{"upstream failure", "outcome", "warn", "status=502 bytes=0 reason=fetch_failed delivered_bytes=120"},
		{"partial delivery", "outcome", "warn", "status=200 bytes=16 reason=delivery_error delivered_bytes=7"},
		{"denied response", "outcome", "block", "status=403 bytes=0 reason=compressed_response delivered_bytes=7"},
	}
	pub, priv := testKeyPair(t)
	if *update {
		var vectors []vector
		for _, tc := range want {
			ar := fixedActionRecord(0, receipt.GenesisHash)
			ar.Transport, ar.Method = "fetch", "GET"
			ar.DecisionPhase, ar.Verdict, ar.Pattern = tc.phase, tc.verdict, tc.pattern
			if tc.phase == receipt.DecisionPhaseOutcome {
				ar.Layer = "outcome"
			}
			r, err := receipt.Sign(ar, priv)
			if err != nil {
				t.Fatal(err)
			}
			vectors = append(vectors, vector{tc.name, r})
		}
		writeJSONPretty(t, path, vectors)
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != len(want) {
		t.Fatalf("vectors=%d want=%d", len(vectors), len(want))
	}
	for i, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			ar := v.Receipt.ActionRecord
			if exp := want[i]; v.Name != exp.name || ar.DecisionPhase != exp.phase || ar.Verdict != exp.verdict || ar.Pattern != exp.pattern {
				t.Fatalf("vector %d = %q %s/%s %q, want %q %s/%s %q", i, v.Name, ar.DecisionPhase, ar.Verdict, ar.Pattern, exp.name, exp.phase, exp.verdict, exp.pattern)
			}
			if err := receipt.VerifyWithKey(v.Receipt, hex.EncodeToString(pub)); err != nil {
				t.Fatal(err)
			}
			// The dashboard uses this production projection of the observation.
			e := evidenceview.ExplainReceipt(v.Receipt)
			if e.Verdict.Detail != ar.Verdict || e.DecisionPhase.Detail != ar.DecisionPhase || ar.Pattern != "" && e.Pattern.Detail != ar.Pattern {
				t.Fatalf("dashboard projection lost outcome: %+v", e)
			}
			v.Receipt.ActionRecord.Pattern += " tampered"
			if err := receipt.VerifyWithKey(v.Receipt, hex.EncodeToString(pub)); err == nil {
				t.Fatal("unsigned outcome mutation accepted")
			}
		})
	}
}
