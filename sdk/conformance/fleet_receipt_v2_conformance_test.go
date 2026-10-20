// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
)

var updateFleetReceiptV2 = flag.Bool("update-fleet-receipt-v2", false, "generate fleet receipt v2 fixtures")

const fleetV2FixtureDir = "testdata/fleet-receipt-v2"

var fleetV2FixtureHashes = map[string]string{
	"valid-l1":               "05a8183046ed2663ec0e50f2944b04a12d80cc1c222a1d1bd17731c681d2b7b2",
	"same-namespace-overlap": "a6343cb4b7adb0fbeb827cab7ab54dddd1498fd0f7ce3575465a141c0616bfe3",
	"missing-chain":          "81223b1d4c4eca15a5c5266e4e29430913a7694f7a5727b0c94ab790c858a76a",
	"mismatched-version":     "3e026c8d28973a2bc880a3f4ff89d8319af6091d7739167a7e5e7b5177038505",
	"unknown-version":        "a06517f31437e43c6a50a320106f1a6ee5d59531367a231b9eff985798b81303",
}

// fleetV2RejectionReasons pins each negative fixture to the rule that must
// refuse it. The fixtures reuse the valid report's signature over a changed
// payload, so a verifier that skipped the named rule would still refuse them
// for a bad signature or non-canonical bytes; an err != nil check alone would
// not notice.
var fleetV2RejectionReasons = map[string]string{
	"same-namespace-overlap": "source batches overlap or are reordered",
	"missing-chain":          "v2 source batch chain required",
	"mismatched-version":     "predicateType/schemaVersion mismatch",
	"unknown-version":        "predicateType/schemaVersion mismatch",
}

func fleetV2Statement() fleetreceipt.Statement {
	s := validFleetReceiptStatement()
	s.PredicateType = fleetreceipt.PredicateTypeV2
	s.Predicate.SchemaVersion = 2
	s.Predicate.SourceBatches[0].Chain = &fleetreceipt.ChainIdentity{EntryVersion: 2, SessionID: "run-a"}
	b := s.Predicate.SourceBatches[0]
	b.BatchID = "batch-run-b"
	b.Chain = &fleetreceipt.ChainIdentity{EntryVersion: 2, SessionID: "run-b"}
	s.Predicate.SourceBatches = append(s.Predicate.SourceBatches, b)
	s.Subject = append(s.Subject, fleetreceipt.Subject{Name: fmt.Sprintf("conductor-audit-batch:%s/%s/%s/%s", b.OrgID, b.FleetID, b.InstanceID, b.BatchID), Digest: fleetreceipt.Digest{SHA256: b.EnvelopeHash}})
	s.Predicate.Summary.TotalActions *= 2
	for _, m := range []map[string]uint64{s.Predicate.Summary.ByFollower, s.Predicate.Summary.ByTransport, s.Predicate.Summary.ByActionType, s.Predicate.Summary.ByVerdict, s.Predicate.Summary.ByLayer, s.Predicate.Summary.BySeverity} {
		for k := range m {
			m[k] *= 2
		}
	}
	s.Predicate.Completeness.ObservedActions *= 2
	s.Predicate.Completeness.MediatedActions *= 2
	return s
}

func TestGenerateFleetReceiptV2Corpus(t *testing.T) {
	if !*updateFleetReceiptV2 {
		t.Skip("pass -update-fleet-receipt-v2")
	}
	_, priv := keyFromSeed(seedFleetReportSigner)
	if err := os.MkdirAll(fleetV2FixtureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"valid-l1", "same-namespace-overlap", "missing-chain", "mismatched-version", "unknown-version"} {
		s := fleetV2Statement()
		env, err := fleetreceipt.SignStatement(s, fleetReportSignerKeyID, priv)
		if err != nil {
			t.Fatal(err)
		}
		var data []byte
		switch name {
		case "valid-l1":
			data, err = marshalFleetEnvelopeBytes(env)
		case "same-namespace-overlap":
			s.Predicate.SourceBatches[1].Chain = s.Predicate.SourceBatches[0].Chain
		case "missing-chain":
			s.Predicate.SourceBatches[0].Chain = nil
		case "mismatched-version":
			s.PredicateType = fleetreceipt.PredicateType
		case "unknown-version":
			s.Predicate.SchemaVersion = 99
		}
		if name != "valid-l1" {
			data, err = buildTamperedPayloadEnvelope(env, s)
		}
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(fleetV2FixtureDir, name+".dsse.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		t.Logf("%s %x", name, sum)
	}
}

func TestFleetReceiptV2Conformance(t *testing.T) {
	pub, _ := keyFromSeed(seedFleetReportSigner)
	if len(fleetV2FixtureHashes) != 5 {
		t.Fatal("v2 fixture manifest incomplete")
	}
	for name, pin := range fleetV2FixtureHashes {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Clean(filepath.Join(fleetV2FixtureDir, name+".dsse.json")))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != pin {
				t.Fatal("frozen fixture changed")
			}
			result, err := fleetreceipt.Verify(data, fleetReceiptTrustedKeyMap(pub))
			if name == "valid-l1" {
				if err != nil {
					t.Fatal(err)
				}
				if result.SourceBatches != 2 || result.TotalActions != 20 {
					t.Fatal("source set or summary lost")
				}
			} else if err == nil {
				t.Fatal("invalid v2 report accepted")
			} else if !strings.Contains(err.Error(), fleetV2RejectionReasons[name]) {
				t.Fatalf("rejected for the wrong reason: %v, want %q", err, fleetV2RejectionReasons[name])
			}
		})
	}
}
