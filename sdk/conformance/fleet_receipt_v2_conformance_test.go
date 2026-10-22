// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

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

func fleetReceiptV2Schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schemaFile, err := os.Open("../../schemas/fleet-receipt-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = schemaFile.Close() }()
	schemaDoc, err := jsonschema.UnmarshalJSON(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	const schemaResource = "fleet-receipt-v2.json"
	if err := compiler.AddResource(schemaResource, schemaDoc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaResource)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func TestFleetReceiptV2NamespaceSchema(t *testing.T) {
	schema := fleetReceiptV2Schema(t)
	for _, field := range []string{"sessionId", "chainKind", "writerInstanceId"} {
		for _, tc := range []struct {
			name, value string
			valid       bool
		}{
			{"ordinary", "namespace-a", true},
			{"empty", "", false},
			{"NUL", "before\x00after", false},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				s := fleetV2Statement()
				s.Predicate.SourceBatches[0].Chain = &fleetreceipt.ChainIdentity{EntryVersion: 3, SessionID: "run-a", ChainKind: "recorder", WriterInstanceID: "writer-a"}
				raw, err := json.Marshal(s)
				if err != nil {
					t.Fatal(err)
				}
				instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				// Set the JSON property after marshaling so omitempty cannot turn
				// an explicit empty string into a missing required property.
				predicate := instance.(map[string]any)["predicate"].(map[string]any)
				batch := predicate["sourceBatches"].([]any)[0].(map[string]any)
				batch["chain"].(map[string]any)[field] = tc.value
				if err := schema.Validate(instance); (err == nil) != tc.valid {
					t.Fatalf("schema validation=%v, want valid=%v", err, tc.valid)
				}
			})
		}
	}
}

func TestFleetReceiptV2Conformance(t *testing.T) {
	pub, _ := keyFromSeed(seedFleetReportSigner)
	schema := fleetReceiptV2Schema(t)
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
			envelope, err := fleetreceipt.UnmarshalEnvelope(data)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			schemaErr := schema.Validate(instance)
			// Overlap is structurally valid; cross-batch range comparisons belong
			// to runtime validation, whose refusal reason is checked below.
			wantSchemaValid := name == "valid-l1" || name == "same-namespace-overlap"
			if (schemaErr == nil) != wantSchemaValid {
				t.Fatalf("schema validation=%v, want valid=%v", schemaErr, wantSchemaValid)
			}
			if _, err := fleetreceipt.ParseStatement(payload); err != nil && schemaErr == nil {
				t.Fatalf("typed decoder rejected schema-valid statement: %v", err)
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

func TestFleetReceiptV2HistorySchema(t *testing.T) {
	schema := fleetReceiptV2Schema(t)
	for _, tc := range []struct {
		name, continuity string
		valid            bool
	}{{"unproven", fleetreceipt.ContinuityUnproven, true}, {"unsupported", "verified", false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := fleetV2Statement()
			gaps, multiple := fleetreceipt.HistoryFacts(s.Predicate.SourceBatches, nil)
			s.Predicate.History = &fleetreceipt.History{Continuity: tc.continuity, MultipleSessions: multiple, Sessions: []fleetreceipt.ObservedChain{}, Gaps: gaps, Retention: fleetreceipt.RetentionCoverage{HistoryUnknown: true}}
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err = schema.Validate(instance); (err == nil) != tc.valid {
				t.Fatalf("schema=%v want valid=%t", err, tc.valid)
			}
			if err = s.Validate(); (err == nil) != tc.valid {
				t.Fatalf("runtime=%v want valid=%t", err, tc.valid)
			}
		})
	}
}

func TestFleetReceiptV2ObservationTimestampSchema(t *testing.T) {
	schema := fleetReceiptV2Schema(t)
	for _, field := range []string{"firstReceived", "lastReceived"} {
		for _, tc := range []struct {
			name, timestamp string
			valid           bool
		}{
			{"utc", "2026-01-01T00:00:00Z", true},
			{"fractional_utc", "2026-01-01T00:00:00.123Z", true},
			{"offset", "2026-01-01T01:00:00+01:00", false},
			{"malformed", "not-a-timestamp", false},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				s := fleetV2Statement()
				b := s.Predicate.SourceBatches[0]
				o := fleetreceipt.ObservedChain{InstanceID: b.InstanceID, Chain: *b.Chain, SeqStart: b.SeqStart, SeqEnd: b.SeqEnd, FirstReceived: "2026-01-01T00:00:00Z", LastReceived: "2026-01-02T00:00:00Z"}
				if field == "firstReceived" {
					o.FirstReceived = tc.timestamp
				} else {
					o.LastReceived = tc.timestamp
				}
				observations := []fleetreceipt.ObservedChain{o}
				gaps, multiple := fleetreceipt.HistoryFacts(s.Predicate.SourceBatches, observations)
				s.Predicate.History = &fleetreceipt.History{Continuity: fleetreceipt.ContinuityUnproven, MultipleSessions: multiple, Sessions: observations, Gaps: gaps, Retention: fleetreceipt.RetentionCoverage{HistoryUnknown: true}}
				raw, err := json.Marshal(s)
				if err != nil {
					t.Fatal(err)
				}
				instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				if err = schema.Validate(instance); (err == nil) != tc.valid {
					t.Fatalf("schema validation=%v want valid=%t", err, tc.valid)
				}
				if err = s.Validate(); (err == nil) != tc.valid {
					t.Fatalf("runtime validation=%v want valid=%t", err, tc.valid)
				}
			})
		}
	}
}
