//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestV3WriterObservationsAndMalformedSeparation(t *testing.T) {
	handler, store, priv := testHandler(t)
	makeBatch := func(id, session string) (conductor.AuditBatchEnvelope, []byte) {
		return sessionEnvelope(t, priv, id, session, 0, 3)
	}
	post := func(env conductor.AuditBatchEnvelope, payload []byte) int {
		return postBatch(t, handler, env, payload).Code
	}
	key := "audit-signer"

	defer func() { _ = store.Close() }()
	sign := func(env conductor.AuditBatchEnvelope) conductor.AuditBatchEnvelope {
		t.Helper()
		signed, err := auditbatcher.SignEnvelope(env, key, priv)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	env, payload := makeBatch("first", "session-a")
	if got := post(env, payload); got != http.StatusAccepted {
		t.Fatalf("first=%d", got)
	}
	second, raw := makeBatch("writer-two", "session-a")
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for i := range entries {
		entries[i].WriterInstanceID = "writer-two"
		if i > 0 {
			entries[i].PrevHash = entries[i-1].Hash
		}
		entries[i].Hash = recorder.ComputeHash(entries[i])
		entries[i].Detail = entries[i].RawDetail
		line, e := json.Marshal(entries[i])
		if e != nil {
			t.Fatal(e)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	raw = buf.Bytes()
	sum := sha256.Sum256(raw)
	second.PayloadSHA256 = hex.EncodeToString(sum[:])
	second.PayloadBytes = uint64(len(raw))
	second.Chain.WriterInstanceID = "writer-two"
	second.Chain.SegmentHeadHash = entries[0].Hash
	second.Chain.SegmentTailHash = entries[len(entries)-1].Hash
	second.Chain.CheckpointHash = entries[len(entries)-1].Hash
	if got := post(sign(second), raw); got != http.StatusAccepted {
		t.Fatalf("writer-only namespace=%d", got)
	}
	var sessions, chains int
	if err = store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_session_observations").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err = store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_chain_observations").Scan(&chains); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || chains != 2 {
		t.Fatalf("sessions/chains=%d/%d", sessions, chains)
	}
	// A new unvalidated envelope label cannot grant namespace separation.
	bad, badPayload := makeBatch("unbound", "session-b")
	bad.Chain.WriterInstanceID = "unsigned-payload-writer"
	if got := post(sign(bad), badPayload); got != http.StatusConflict {
		t.Fatalf("mismatched payload separated history: %d", got)
	}
	if err = store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_session_observations").Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("rejected session rows=%d err=%v", sessions, err)
	}
}
