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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// realRunEvidence drives the shipped recorder and audit producer for one
// process lifetime and returns the single signed batch they emit. The
// namespace builder tests elsewhere in this package build their entries by
// hand; this is the only fixture whose entries, hashes, checkpoint and
// envelope come from the code a follower actually runs.
//
// It exercises the current writer (recorder entry version 2). No shipped
// writer emits version 3 entries yet, so the version 3 path is covered only by
// the synthetic fixtures.
func realRunEvidence(t *testing.T, priv ed25519.PrivateKey, recorderDir string, actionIDs []string) controlplane.AuditBatchEvidence {
	t.Helper()
	queue, err := auditbatcher.Open(auditbatcher.Config{Dir: filepath.Join(t.TempDir(), "queue"), AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	producer, err := auditbatcher.NewProducer(auditbatcher.ProducerConfig{
		Queue: queue, OrgID: testOrgID, FleetID: testFleetID, InstanceID: testInstanceID,
		AuditSignerKeyID: testAuditKeyID, RecorderKeyID: "recorder-key-1", AuditSigner: priv,
		RecorderPublicKey: priv.Public().(ed25519.PublicKey),
		Now:               func() time.Time { return testWindowStart.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = producer.Close() })
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: recorderDir, CheckpointInterval: len(actionIDs), SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	rec.SetObserver(producer)
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range actionIDs {
		rcpt := testActionReceipt(t, priv, id, receipt.ActionRead, "allow", "fetch", "url", "low")
		if err := rec.Record(recorder.Entry{SessionID: session, Type: "action_receipt", EventKind: string(receipt.ActionRead), Transport: "fetch", Summary: id, Detail: rcpt}); err != nil {
			t.Fatal(err)
		}
	}
	var lease *auditbatcher.Lease
	testwait.For(t, 2*time.Second, func() bool {
		var claimErr error
		lease, claimErr = queue.Claim()
		return claimErr == nil && lease != nil
	}, "producer emitted no audit batch")
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	env := lease.Batch.Envelope
	hash, err := env.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	return controlplane.AuditBatchEvidence{
		Envelope: env,
		Payload:  lease.Batch.Payload,
		Summary:  controlplane.AuditBatchSummary{EnvelopeHash: hash, ReceivedAt: testWindowStart.Add(time.Minute), SignatureKeyIDs: []string{testAuditKeyID}},
	}
}

// TestBuildRealRecorderRestartAcrossRuns reproduces the failure this version
// exists for: one follower restarts against the same evidence directory, the
// recorder starts a fresh run session, and sequence numbers begin again at the
// start. Version 1 refuses the whole window; version 2 keeps both runs.
func TestBuildRealRecorderRestartAcrossRuns(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	first := realRunEvidence(t, priv, dir, []string{"run-one-a", "run-one-b"})
	second := realRunEvidence(t, priv, dir, []string{"run-two-a", "run-two-b"})
	if first.Envelope.SeqStart != second.Envelope.SeqStart {
		t.Fatalf("restart did not reuse sequence numbers: %d and %d", first.Envelope.SeqStart, second.Envelope.SeqStart)
	}
	if first.Envelope.BatchID == second.Envelope.BatchID {
		t.Fatal("batches share an id; fixture cannot represent two stored batches")
	}
	evidence := []controlplane.AuditBatchEvidence{first, second}
	opts := namespaceOptions(t, pub)

	opts.ReportVersion = fleetreceipt.SchemaVersionV1
	if _, err := Build(t.Context(), staticEvidenceSource{evidence: evidence}, opts); err == nil || !strings.Contains(err.Error(), "overlap or are reordered") {
		t.Fatalf("v1 restart window: %v", err)
	}

	opts.ReportVersion = 0
	result, err := Build(t.Context(), staticEvidenceSource{evidence: evidence}, opts)
	if err != nil {
		t.Fatalf("v2 restart window: %v", err)
	}
	batches := result.Statement.Predicate.SourceBatches
	if len(batches) != 2 || batches[0].Chain.SessionID == batches[1].Chain.SessionID {
		t.Fatalf("restart runs not separated into namespaces: %+v", batches)
	}
	if result.Statement.Predicate.Summary.TotalActions != 4 {
		t.Fatalf("restart dropped actions: total=%d want 4", result.Statement.Predicate.Summary.TotalActions)
	}
	if _, err := fleetreceipt.VerifyEnvelope(result.Envelope, map[string]ed25519.PublicKey{testReportKeyID: opts.Signer.Public().(ed25519.PublicKey)}); err != nil {
		t.Fatalf("offline verification: %v", err)
	}
}

// TestBuildV2RequiresEnrolledAuditKey pins the outcome of the unkeyed case:
// without an audit key resolver the builder cannot authenticate the envelope
// the namespace is derived from, so no v2 report is minted. The receipt
// verification step refuses first for a batch that holds action receipts, and
// a report needs at least one, so the explicit v2 key check is a second line
// of defense whose removal does not change this outcome.
func TestBuildV2RequiresEnrolledAuditKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evidence := []controlplane.AuditBatchEvidence{namespaceEvidence(t, priv, "unkeyed", "run", "", 1)}
	opts := namespaceOptions(t, pub)
	opts.AuditKeys = nil
	if _, err := Build(t.Context(), staticEvidenceSource{evidence: evidence}, opts); err == nil || !strings.Contains(err.Error(), "no enrolled audit key") {
		t.Fatalf("v2 without audit key: %v", err)
	}
}

// TestBuildV1OutputByteStable pins the version 1 report bytes. The digest was
// produced by the builder before the version 2 change on identical input and
// matches this tree's output, so a change that alters version 1 encoding, or
// stops honoring an explicit version 1 request, fails here.
func TestBuildV1OutputByteStable(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	evidence := []controlplane.AuditBatchEvidence{
		testEvidence(t, priv, "b1", 1, []receipt.Receipt{testActionReceipt(t, priv, "x1", receipt.ActionRead, "allow", "fetch", "url", "low")}, 2),
		testEvidence(t, priv, "b2", 10, []receipt.Receipt{testActionReceipt(t, priv, "x2", receipt.ActionRead, "block", "mcp", "dlp", "high")}, 0),
	}
	opts := namespaceOptions(t, pub)
	opts.Signer = priv
	opts.ReportVersion = fleetreceipt.SchemaVersionV1
	result, err := Build(t.Context(), staticEvidenceSource{evidence: evidence}, opts)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(result.Envelope.Payload + "\n" + result.Envelope.Signatures[0].Sig))
	const want = "6ef2da5a55f8e06f7baf965da792854866e12b04face63e150eecbada9fd8684"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("v1 report bytes changed: %s want %s", got, want)
	}
	if result.Statement.PredicateType != fleetreceipt.PredicateType || result.Statement.Predicate.SourceBatches[0].Chain != nil {
		t.Fatal("explicit v1 request produced v2 shape")
	}
}
