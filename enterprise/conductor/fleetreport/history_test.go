//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleetreport

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
)

func TestBuildDurableHistorySnapshot(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := controlplane.OpenSQLiteAuditStore(t.Context(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	for _, tc := range []struct {
		id, session string
		start       uint64
	}{{"a", "run-a", 1}, {"a-next", "run-a", 10}, {"b", "run-b", 1}} {
		ev := namespaceEvidence(t, priv, tc.id, tc.session, "", tc.start)
		if _, err = store.IngestAuditBatch(t.Context(), controlplane.AcceptedAuditBatch{Identity: controlplane.FollowerIdentity{Environment: "prod", OrgID: ev.Envelope.OrgID, FleetID: ev.Envelope.FleetID, InstanceID: ev.Envelope.InstanceID}, Envelope: ev.Envelope, EnvelopeHash: ev.Summary.EnvelopeHash, Payload: ev.Payload, ReceivedAt: ev.Summary.ReceivedAt}); err != nil {
			t.Fatal(err)
		}
	}
	opts := namespaceOptions(t, pub)
	result, err := Build(t.Context(), store, opts)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := fleetreceipt.VerifyEnvelope(result.Envelope, map[string]ed25519.PublicKey{testReportKeyID: opts.Signer.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := verified.Statement.Predicate.History
	if h == nil || h.Continuity != fleetreceipt.ContinuityUnproven || !h.MultipleSessions || len(h.Sessions) != 2 || len(h.Gaps) != 1 || h.Gaps[0].SeqStart != 3 || h.Gaps[0].SeqEnd != 9 || h.Retention.HistoryUnknown {
		t.Fatalf("history=%+v", h)
	}
	if _, err = store.PruneAuditBatchesBefore(t.Context(), testWindowStart.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// After payload retirement the durable session context still accompanies a later batch.
	ev := namespaceEvidence(t, priv, "later", "run-a", "", 20)
	if _, err = store.IngestAuditBatch(t.Context(), controlplane.AcceptedAuditBatch{Identity: controlplane.FollowerIdentity{Environment: "prod", OrgID: ev.Envelope.OrgID, FleetID: ev.Envelope.FleetID, InstanceID: ev.Envelope.InstanceID}, Envelope: ev.Envelope, EnvelopeHash: ev.Summary.EnvelopeHash, Payload: ev.Payload, ReceivedAt: ev.Summary.ReceivedAt}); err != nil {
		t.Fatal(err)
	}
	result, err = Build(t.Context(), store, opts)
	if err != nil {
		t.Fatal(err)
	}
	h = result.Statement.Predicate.History
	if len(h.Sessions) != 2 || h.Retention.PrunedBefore == "" || !h.MultipleSessions || result.Statement.Predicate.Summary.TotalActions != 1 {
		t.Fatalf("post-prune=%+v", h)
	}
}
