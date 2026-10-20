// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package fleetreceipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"slices"
	"testing"
)

func namespacedStatement() Statement {
	s := testStatement()
	s.PredicateType = PredicateTypeV2
	s.Predicate.SchemaVersion = SchemaVersionV2
	for i := range s.Predicate.SourceBatches {
		s.Predicate.SourceBatches[i].Chain = &ChainIdentity{EntryVersion: 2, SessionID: []string{"run-a", "run-b"}[i]}
	}
	s.Predicate.SourceBatches[1].SeqStart = s.Predicate.SourceBatches[0].SeqStart
	s.Predicate.SourceBatches[1].SeqEnd = s.Predicate.SourceBatches[0].SeqEnd
	return s
}

func TestV2NamespacesAndVersionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*Statement)
		valid bool
	}{
		{"independent runs", func(*Statement) {}, true},
		{"independent v3 writers", func(s *Statement) {
			for i := range s.Predicate.SourceBatches {
				s.Predicate.SourceBatches[i].Chain = &ChainIdentity{EntryVersion: 3, SessionID: "same-run", ChainKind: "recorder", WriterInstanceID: []string{"writer-a", "writer-b"}[i]}
			}
		}, true},
		{"same namespace overlap", func(s *Statement) { s.Predicate.SourceBatches[1].Chain = s.Predicate.SourceBatches[0].Chain }, false},
		{"reordered namespaces", func(s *Statement) { slices.Reverse(s.Predicate.SourceBatches) }, false},
		{"duplicate across namespaces", func(s *Statement) { s.Predicate.SourceBatches[1].BatchID = s.Predicate.SourceBatches[0].BatchID }, false},
		{"missing namespace", func(s *Statement) { s.Predicate.SourceBatches[0].Chain = nil }, false},
		{"empty session", func(s *Statement) { s.Predicate.SourceBatches[0].Chain.SessionID = "" }, false},
		{"NUL session", func(s *Statement) { s.Predicate.SourceBatches[0].Chain.SessionID = "a\x00b" }, false},
		{"legacy with writer", func(s *Statement) { s.Predicate.SourceBatches[0].Chain.WriterInstanceID = "writer" }, false},
		{"v3 without writer", func(s *Statement) {
			s.Predicate.SourceBatches[0].Chain.EntryVersion = 3
			s.Predicate.SourceBatches[0].Chain.ChainKind = "recorder"
		}, false},
		{"unknown entry version", func(s *Statement) { s.Predicate.SourceBatches[0].Chain.EntryVersion = 4 }, false},
		{"wrong follower", func(s *Statement) { s.Predicate.SourceBatches[0].FleetID = "foreign" }, false},
		{"unknown schema", func(s *Statement) { s.Predicate.SchemaVersion = 3 }, false},
		{"v1 URI v2 schema", func(s *Statement) { s.PredicateType = PredicateType }, false},
		{"v2 URI v1 schema", func(s *Statement) { s.Predicate.SchemaVersion = 1 }, false},
		{"v1 cannot carry namespace", func(s *Statement) { s.PredicateType = PredicateType; s.Predicate.SchemaVersion = 1 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := namespacedStatement()
			tc.edit(&s)
			if err := s.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate=%v valid=%v", err, tc.valid)
			}
		})
	}
}

func TestV2SignedNamespaceTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignStatement(namespacedStatement(), "report-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelope(env, map[string]ed25519.PublicKey{"report-key": pub}); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseStatement(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.Predicate.SourceBatches[0].Chain.SessionID = "forged"
	slices.SortFunc(s.Predicate.SourceBatches, CompareSourceBatches)
	raw, err = CanonicalStatement(s)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = base64.StdEncoding.EncodeToString(raw)
	if _, err := VerifyEnvelope(env, map[string]ed25519.PublicKey{"report-key": pub}); err == nil {
		t.Fatal("tampered namespace accepted")
	}
	// Unknown fields cannot become unsigned grouping advice after typed decoding.
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	tree["sessionId"] = "unsigned"
	raw, err = json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = base64.StdEncoding.EncodeToString(raw)
	if _, err := VerifyEnvelope(env, map[string]ed25519.PublicKey{"report-key": pub}); err == nil {
		t.Fatal("unknown grouping field accepted")
	}
}
