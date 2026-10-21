// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package fleetreceipt

import "testing"

func TestHistoryFactsAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Statement)
		valid  bool
	}{
		{"unproven", func(*Statement) {}, true},
		{"claims-continuity", func(s *Statement) { s.Predicate.History.Continuity = "verified" }, false},
		{"hidden-multiple-sessions", func(s *Statement) { s.Predicate.History.MultipleSessions = false }, false},
		{"invented-gap", func(s *Statement) {
			s.Predicate.History.Gaps = append(s.Predicate.History.Gaps, SequenceGap{InstanceID: "other", Chain: ChainIdentity{EntryVersion: 2, SessionID: "x"}, SeqStart: 1, SeqEnd: 2})
		}, false},
		{"unknown-coverage", func(s *Statement) { s.Predicate.History.Retention.HistoryUnknown = false }, false},
		{"v1-history", func(s *Statement) { s.PredicateType = PredicateType; s.Predicate.SchemaVersion = 1 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := namespacedStatement()
			gaps, multiple := HistoryFacts(s.Predicate.SourceBatches, nil)
			s.Predicate.History = &History{Continuity: ContinuityUnproven, MultipleSessions: multiple, Sessions: []ObservedChain{}, Gaps: gaps, Retention: RetentionCoverage{HistoryUnknown: true}}
			tc.mutate(&s)
			if err := s.Validate(); (err == nil) != tc.valid {
				t.Fatalf("validation=%v want valid=%t", err, tc.valid)
			}
		})
	}
	t.Run("selected-gap-not-prefix", func(t *testing.T) {
		chain := &ChainIdentity{EntryVersion: 2, SessionID: "a"}
		b := []SourceBatch{{InstanceID: "one", Chain: chain, SeqStart: 10, SeqEnd: 12}, {InstanceID: "one", Chain: chain, SeqStart: 20, SeqEnd: 21}}
		gaps, multiple := HistoryFacts(b, nil)
		if multiple || len(gaps) != 1 || gaps[0].SeqStart != 13 || gaps[0].SeqEnd != 19 {
			t.Fatalf("gaps=%+v multiple=%t", gaps, multiple)
		}
	})
}
