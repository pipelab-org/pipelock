//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func legacySessionFixture(t *testing.T) (AuditBatchEnvelope, []recorder.Entry) {
	t.Helper()
	env := testAuditBatch()
	entries := []recorder.Entry{
		{Version: 2, Sequence: 10, Timestamp: testNow, SessionID: "run-1", Type: "capture", PrevHash: testHash("aa")},
		{Version: 2, Sequence: 11, Timestamp: testNow, SessionID: "run-1", Type: "checkpoint", Detail: recorder.CheckpointDetail{Signature: strings.TrimPrefix(env.Chain.CheckpointSignature, SignaturePrefixEd25519)}},
	}
	entries[0].Hash = recorder.ComputeHash(entries[0])
	entries[1].PrevHash = entries[0].Hash
	entries[1].Hash = recorder.ComputeHash(entries[1])
	env.SeqStart, env.Chain.SeqStart = 10, 10
	env.SeqEnd, env.Chain.SeqEnd = 11, 11
	env.EventCount = 2
	env.Chain.SegmentHeadHash = entries[0].Hash
	env.Chain.SegmentTailHash = entries[1].Hash
	env.Chain.CheckpointSeq = 11
	env.Chain.CheckpointHash = entries[1].Hash
	return env, entries
}

func bindLegacySessionPayload(t *testing.T, env *AuditBatchEnvelope, entries []recorder.Entry) []byte {
	t.Helper()
	var payload []byte
	for _, entry := range entries {
		raw, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, raw...)
		payload = append(payload, '\n')
	}
	env.PayloadBytes = uint64(len(payload))
	env.PayloadSHA256 = testBytesHash(payload)
	return payload
}

func TestLegacyPayloadSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*AuditBatchEnvelope, []recorder.Entry)
		raw    string
		want   string
	}{
		{name: "valid_partial_segment", want: "run-1"},
		{name: "missing_session", mutate: func(_ *AuditBatchEnvelope, e []recorder.Entry) { e[0].SessionID = "" }},
		{name: "mixed_sessions", mutate: func(_ *AuditBatchEnvelope, e []recorder.Entry) { e[1].SessionID = "another-run" }},
		{name: "mixed_sessions_valid_hashes", mutate: func(a *AuditBatchEnvelope, e []recorder.Entry) {
			e[1].SessionID = "another-run"
			e[1].Hash = recorder.ComputeHash(e[1])
			a.Chain.SegmentTailHash = e[1].Hash
			a.Chain.CheckpointHash = e[1].Hash
		}},
		{name: "hash_mismatch", mutate: func(_ *AuditBatchEnvelope, e []recorder.Entry) { e[1].Summary = "rewritten" }},
		{name: "namespace_decoration", mutate: func(_ *AuditBatchEnvelope, e []recorder.Entry) { e[0].ChainKind = "proxy" }},
		{name: "unsupported_version", mutate: func(_ *AuditBatchEnvelope, e []recorder.Entry) { e[0].Version = 99 }},
		{name: "mixed_versions", mutate: func(_ *AuditBatchEnvelope, e []recorder.Entry) { e[0].Version = 1 }},
		{name: "sequence_gap", mutate: func(a *AuditBatchEnvelope, e []recorder.Entry) {
			e[1].Sequence = 12
			a.SeqEnd = 12
			a.Chain.SeqEnd = 12
		}},
		{name: "link_mismatch", mutate: func(_ *AuditBatchEnvelope, e []recorder.Entry) { e[1].PrevHash = recorder.GenesisHash }},
		{name: "envelope_range", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.SeqStart = 9; a.Chain.SeqStart = 9 }},
		{name: "envelope_head", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.Chain.SegmentHeadHash = testHash("ff") }},
		{name: "envelope_count", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.EventCount++ }},
		{name: "envelope_checkpoint_hash", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.Chain.CheckpointHash = testHash("ff") }},
		{name: "envelope_checkpoint_seq", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.Chain.CheckpointSeq = 10 }},
		{name: "envelope_checkpoint_signature", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.Chain.CheckpointSignature = testSignature("ff") }},
		{name: "envelope_session_not_authority", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.Chain.SessionID = "claimed-session" }},
		{name: "v3_uses_existing_comparator", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.Chain.EntryVersion = 3 }},
		{name: "invalid_envelope", mutate: func(a *AuditBatchEnvelope, _ []recorder.Entry) { a.BatchID = "" }},
		{name: "malformed_json", raw: "{"},
		{name: "duplicate_key", raw: `{"v":2,"v":2}`},
		{name: "empty_entries", raw: "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, entries := legacySessionFixture(t)
			if tc.mutate != nil {
				tc.mutate(&env, entries)
			}
			payload := bindLegacySessionPayload(t, &env, entries)
			if tc.raw != "" {
				payload = []byte(tc.raw)
				env.PayloadBytes = uint64(len(payload))
				env.PayloadSHA256 = testBytesHash(payload)
			}
			if tc.name == "mixed_sessions_valid_hashes" {
				if err := env.Validate(); err != nil {
					t.Fatalf("invalid fixture envelope: %v", err)
				}
				if err := env.ValidatePayload(payload); err != nil {
					t.Fatal(err)
				}
				if err := ValidateAuditSegment(env.Chain, entries); err != nil {
					t.Fatalf("invalid fixture segment: %v", err)
				}
				for _, entry := range entries {
					if entry.Hash != recorder.ComputeHash(entry) {
						t.Fatal("fixture hash invalid")
					}
				}
			}
			got, err := env.LegacyPayloadSession(t.Context(), payload)
			if err != nil || got != tc.want {
				t.Fatalf("session=%q err=%v want=%q", got, err, tc.want)
			}
		})
	}
}

func TestLegacyPayloadSessionBindingAndLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*AuditBatchEnvelope, []byte) []byte
	}{
		{"digest", func(a *AuditBatchEnvelope, p []byte) []byte { a.PayloadSHA256 = testHash("ff"); return p }},
		{"length", func(a *AuditBatchEnvelope, p []byte) []byte { a.PayloadBytes++; return p }},
		{"oversize", func(_ *AuditBatchEnvelope, _ []byte) []byte { return make([]byte, MaxAuditPayloadBytes+1) }},
		{"empty_session_valid_hash", func(a *AuditBatchEnvelope, _ []byte) []byte {
			_, entries := legacySessionFixture(t)
			for i := range entries {
				entries[i].SessionID = ""
				if i > 0 {
					entries[i].PrevHash = entries[i-1].Hash
				}
				entries[i].Hash = recorder.ComputeHash(entries[i])
			}
			a.Chain.SegmentHeadHash = entries[0].Hash
			a.Chain.SegmentTailHash = entries[1].Hash
			a.Chain.CheckpointHash = entries[1].Hash
			return bindLegacySessionPayload(t, a, entries)
		}},
		{"not_checkpoint", func(a *AuditBatchEnvelope, _ []byte) []byte {
			_, entries := legacySessionFixture(t)
			entries[1].Type = "capture"
			entries[1].Hash = recorder.ComputeHash(entries[1])
			a.Chain.SegmentTailHash = entries[1].Hash
			a.Chain.CheckpointHash = entries[1].Hash
			return bindLegacySessionPayload(t, a, entries)
		}},
		{"bad_checkpoint_detail", func(a *AuditBatchEnvelope, _ []byte) []byte {
			_, entries := legacySessionFixture(t)
			entries[1].Detail = "not a checkpoint"
			entries[1].Hash = recorder.ComputeHash(entries[1])
			a.Chain.SegmentTailHash = entries[1].Hash
			a.Chain.CheckpointHash = entries[1].Hash
			return bindLegacySessionPayload(t, a, entries)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, entries := legacySessionFixture(t)
			payload := bindLegacySessionPayload(t, &env, entries)
			payload = tc.mutate(&env, payload)
			got, err := env.LegacyPayloadSession(t.Context(), payload)
			if got != "" || err != nil {
				t.Fatalf("session=%q err=%v", got, err)
			}
		})
	}
	t.Run("cancellation", func(t *testing.T) {
		env, entries := legacySessionFixture(t)
		payload := bindLegacySessionPayload(t, &env, entries)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		got, err := env.LegacyPayloadSession(ctx, payload)
		if got != "" || !errors.Is(err, context.Canceled) {
			t.Fatalf("session=%q err=%v", got, err)
		}
	})
}

func TestValidateAuditSegmentRejectsSequenceWrap(t *testing.T) {
	env, entries := legacySessionFixture(t)
	entries[0].Sequence = ^uint64(0)
	entries[1].Sequence = 0
	env.Chain.SeqStart = entries[0].Sequence
	env.Chain.SeqEnd = 0
	if err := ValidateAuditSegment(env.Chain, entries); err == nil || !strings.Contains(err.Error(), "seq gap") {
		t.Fatalf("wrap accepted: %v", err)
	}
}

// Cancel while the consumer checks its context, avoiding timing-dependent
// goroutines while exercising cancellation after parsing and during hashing.
type auditCancelOnCheck struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *auditCancelOnCheck) Err() error {
	c.checks--
	if c.checks == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestLegacyPayloadSessionLateCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks int
	}{{"after_parse", 2}, {"during_entry_validation", 3}} {
		t.Run(tc.name, func(t *testing.T) {
			env, entries := legacySessionFixture(t)
			payload := bindLegacySessionPayload(t, &env, entries)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			got, err := env.LegacyPayloadSession(&auditCancelOnCheck{Context: ctx, cancel: cancel, checks: tc.checks}, payload)
			if got != "" || !errors.Is(err, context.Canceled) {
				t.Fatalf("session=%q err=%v", got, err)
			}
		})
	}
}
