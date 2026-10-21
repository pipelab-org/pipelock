//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleetreport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestBuildV1RefusesMixedSessionsWithinLegacyBatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, sessions := range [][3]string{{"run-a", "run-b", "run-b"}, {"", "run-b", "run-b"}, {"run-a", "", ""}, {"run-a", "run-b", "run-a"}} {
		t.Run(fmt.Sprint(sessions), func(t *testing.T) {
			ev := testEvidence(t, priv, "mixed-batch", 1, []receipt.Receipt{
				testActionReceipt(t, priv, "action-a", receipt.ActionRead, "allow", "fetch", "url", "low"),
				testActionReceipt(t, priv, "action-b", receipt.ActionRead, "allow", "fetch", "url", "low"),
			}, 0)
			entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(ev.Payload))
			if err != nil {
				t.Fatal(err)
			}
			for i := range entries {
				entries[i].SessionID = sessions[i]
				if i > 0 {
					entries[i].PrevHash = entries[i-1].Hash
				}
				entries[i].Hash = recorder.ComputeHash(entries[i])
			}
			ev = resignNamespaceEvidence(t, priv, ev, entries)
			// The segment-local contract accepts this authenticated legacy
			// batch, but it cannot establish one recorder run for a report.
			if err := verifySegment(ev.Envelope.BatchID, ev.Envelope.Chain, entries); err != nil {
				t.Fatalf("fixture fails before the run guard: %v", err)
			}
			store, err := controlplane.OpenSQLiteAuditStore(t.Context(), filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if _, err := store.IngestAuditBatch(t.Context(), controlplane.AcceptedAuditBatch{
				Identity: controlplane.FollowerIdentity{Environment: "prod", OrgID: ev.Envelope.OrgID, FleetID: ev.Envelope.FleetID, InstanceID: ev.Envelope.InstanceID},
				Envelope: ev.Envelope, EnvelopeHash: ev.Summary.EnvelopeHash, Payload: ev.Payload, ReceivedAt: ev.Summary.ReceivedAt,
			}); err != nil {
				t.Fatalf("receiver refused the fixture before report minting: %v", err)
			}
			opts := namespaceOptions(t, pub)
			opts.ReportVersion = fleetreceipt.SchemaVersionV1
			result, err := Build(t.Context(), store, opts)
			if err == nil {
				_, verifyErr := fleetreceipt.VerifyEnvelope(result.Envelope, map[string]ed25519.PublicKey{testReportKeyID: opts.Signer.Public().(ed25519.PublicKey)})
				t.Fatalf("mixed-session v1 report signed, offline verification=%v; want refusal", verifyErr)
			}
			if !errors.Is(err, ErrV1MultipleRuns) {
				t.Fatalf("mixed-session v1 report: error=%v, signed=%t; want ErrV1MultipleRuns", err, len(result.Envelope.Signatures) > 0)
			}
			if strings.Contains(err.Error(), "--report-version 2") {
				t.Fatalf("mixed-session refusal suggests an unusable remedy: %v", err)
			}
			opts.ReportVersion = fleetreceipt.SchemaVersionV2
			if _, err := Build(t.Context(), store, opts); err == nil {
				t.Fatal("v2 accepted mixed sessions")
			}
		})
	}
}
