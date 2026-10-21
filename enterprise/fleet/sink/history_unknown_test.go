//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
)

// The sink shares the receiver's coverage contract: an admitted batch whose
// recorder run can't be established marks history as unknown.
func TestUnresolvedLiveIngestMarksHistoryUnknown(t *testing.T) {
	handler, _, priv := testHandler(t)
	store, err := OpenStore(t.Context(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	handler.store = store
	unknown := func() bool {
		t.Helper()
		var v int
		if err := store.db.QueryRowContext(t.Context(), "SELECT history_unknown FROM audit_observation_coverage WHERE id=1").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v != 0
	}
	if unknown() {
		t.Fatal("fresh store reports history unknown before any evidence")
	}

	env, _ := sessionEnvelope(t, priv, "malformed", "run-a", 0, 2)
	payload := []byte("{")
	sum := sha256.Sum256(payload)
	env.PayloadBytes = uint64(len(payload))
	env.PayloadSHA256 = hex.EncodeToString(sum[:])
	env, err = auditbatcher.SignEnvelope(env, "audit-signer", priv)
	if err != nil {
		t.Fatal(err)
	}
	if w := postBatch(t, handler, env, payload); w.Code != http.StatusAccepted {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	if !unknown() {
		t.Fatal("unresolved admitted batch left history_unknown=0")
	}
}
