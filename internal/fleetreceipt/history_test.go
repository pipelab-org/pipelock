// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package fleetreceipt

import (
	"strings"
	"testing"
)

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

func TestHistoryObservationValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*History)
		want   string
	}{
		{"valid", func(*History) {}, ""},
		{"missing_sessions", func(h *History) { h.Sessions = nil }, "must be arrays"},
		{"missing_gaps", func(h *History) { h.Gaps = nil }, "must be arrays"},
		{"missing_instance", func(h *History) { h.Sessions[0].InstanceID = "" }, "invalid observed chain"},
		{"reversed_sequence", func(h *History) { h.Sessions[0].SeqStart = 3 }, "invalid observed chain"},
		{"invalid_chain", func(h *History) { h.Sessions[0].Chain.EntryVersion = 1 }, "unsupported chain entryVersion"},
		{"invalid_first", func(h *History) { h.Sessions[0].FirstReceived = "invalid" }, "history.firstReceived"},
		{"invalid_last", func(h *History) { h.Sessions[0].LastReceived = "invalid" }, "history.lastReceived"},
		{"reversed_arrival", func(h *History) { h.Sessions[0].FirstReceived = "2026-01-03T00:00:00Z" }, "observation arrival range"},
		{"invalid_observation_coverage", func(h *History) { h.Retention.ObservationsSince = "invalid" }, "observationsSince"},
		{"invalid_prune_coverage", func(h *History) { h.Retention.PrunedBefore = "invalid" }, "prunedBefore"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := History{Continuity: ContinuityUnproven, Sessions: []ObservedChain{{InstanceID: "one", Chain: ChainIdentity{EntryVersion: 2, SessionID: "run-a"}, FirstReceived: "2026-01-01T00:00:00Z", LastReceived: "2026-01-02T00:00:00Z", SeqStart: 0, SeqEnd: 2}}, Gaps: []SequenceGap{}, Retention: RetentionCoverage{ObservationsSince: "2026-01-01T00:00:00Z", PrunedBefore: "2025-12-31T00:00:00Z"}}
			tc.mutate(&h)
			err := h.validate(nil)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation=%v want %q", err, tc.want)
			}
		})
	}
}

func TestHistoryGapValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain ChainIdentity
		want  string
	}{
		{"valid", ChainIdentity{EntryVersion: 2, SessionID: "run-a"}, ""},
		{"invalid_chain", ChainIdentity{EntryVersion: 1, SessionID: "run-a"}, "unsupported chain entryVersion"},
		{"missing_instance", ChainIdentity{EntryVersion: 2, SessionID: "run-a"}, "invalid history gap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instance := "one"
			if tc.name == "missing_instance" {
				instance = ""
			}
			batches := []SourceBatch{{InstanceID: instance, Chain: &tc.chain, SeqStart: 0, SeqEnd: 1}, {InstanceID: instance, Chain: &tc.chain, SeqStart: 3, SeqEnd: 4}}
			gaps, multiple := HistoryFacts(batches, nil)
			h := History{Continuity: ContinuityUnproven, Sessions: []ObservedChain{}, Gaps: gaps, MultipleSessions: multiple, Retention: RetentionCoverage{HistoryUnknown: true}}
			err := h.validate(batches)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation=%v want %q", err, tc.want)
			}
		})
	}
}
