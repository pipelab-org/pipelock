//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
)

// An admitted batch whose recorder run can't be established must mark observation
// coverage as history-unknown. Otherwise a signed report could claim complete
// history while unresolved evidence sits in the store.
func TestUnresolvedLiveIngestMarksHistoryUnknown(t *testing.T) {
	pub, priv := testAuditSigner(t)
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	t.Cleanup(func() { _ = store.Close() })
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	query := AuditEvidenceQuery{OrgID: defaultFollowerIdentity().OrgID, FleetID: defaultFollowerIdentity().FleetID, ReceivedFrom: testNow.Add(-time.Hour), ReceivedTo: testNow.Add(time.Hour)}
	snap, err := store.AuditEvidenceSnapshot(t.Context(), query)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Coverage.HistoryUnknown {
		t.Fatal("fresh store reports history unknown before any evidence")
	}

	b := controlplaneSessionBatch(t, priv, "malformed", "s", 0, 2)
	b.Payload = []byte("{")
	sum := sha256.Sum256(b.Payload)
	b.Envelope.PayloadBytes = uint64(len(b.Payload))
	b.Envelope.PayloadSHA256 = hex.EncodeToString(sum[:])
	b.Envelope, err = auditbatcher.SignEnvelope(b.Envelope, testAuditKeyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	if w := auditRunPost(t, handler, b); w.Code != http.StatusAccepted {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	snap, err = store.AuditEvidenceSnapshot(t.Context(), query)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Coverage.HistoryUnknown {
		t.Fatal("unresolved admitted batch left historyUnknown=false")
	}
}
