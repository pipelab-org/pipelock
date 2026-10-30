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
	pub, priv := testKeyPair(t)
	if *update {
		var vectors []vector
		for _, tc := range []struct{ name, phase, verdict, pattern string }{
			{"legacy completion", "outcome", "allow", "status=200 bytes=16 reason=complete"},
			{"admission without outcome", "intent", "allow", ""},
			{"delivered representation", "outcome", "allow", "status=200 bytes=130 reason=complete captured_bytes=16"},
			{"upstream failure", "outcome", "warn", "status=502 bytes=120 reason=fetch_failed captured_bytes=0"},
			{"partial delivery", "outcome", "warn", "status=200 bytes=7 reason=delivery_error captured_bytes=16"},
			{"denied response", "outcome", "block", "status=403 bytes=7 reason=compressed_response captured_bytes=0"},
		} {
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
	if len(vectors) != 6 {
		t.Fatalf("vectors=%d", len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			if err := receipt.VerifyWithKey(v.Receipt, hex.EncodeToString(pub)); err != nil {
				t.Fatal(err)
			}
			// The dashboard uses this production projection of the observation.
			e := evidenceview.ExplainReceipt(v.Receipt)
			ar := v.Receipt.ActionRecord
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
