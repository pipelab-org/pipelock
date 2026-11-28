//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleetreport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/receipt"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestFleetReportRefusesReceiptV3(t *testing.T) {
	path, _ := testreceipt.V3(t, t.TempDir(), false)
	payload, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := testEvidence(t, priv, "audit-1", 1, []receipt.Receipt{
		testActionReceipt(t, priv, "a1", receipt.ActionRead, "allow", "fetch", "url", "low"),
	}, 0)
	ev.Payload = payload
	hash := sha256.Sum256(payload)
	ev.Envelope.PayloadSHA256 = hex.EncodeToString(hash[:])
	ev.Envelope.PayloadBytes = uint64(len(payload))
	ev.Envelope, err = auditbatcher.SignEnvelope(ev.Envelope, testAuditKeyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	ev.Summary.EnvelopeHash, err = ev.Envelope.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Build(t.Context(), staticEvidenceSource{evidence: []controlplane.AuditBatchEvidence{ev}}, Options{
		OrgID: testOrgID, FleetID: testFleetID,
		WindowStart: testWindowStart, WindowEnd: testWindowStart.Add(time.Hour),
		ConductorID: "conductor", ConductorVersion: "example",
		SignerKeyID: testReportKeyID, Signer: priv, AuditKeys: staticAuditKeyResolver(pub),
		GeneratedAt: testWindowStart.Add(time.Minute),
	})
	testreceipt.RequiresV3Refusal(t, err, "fleet report", "fleet reports")
}
