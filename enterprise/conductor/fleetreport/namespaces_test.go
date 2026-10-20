//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleetreport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func namespaceEvidence(t *testing.T, priv ed25519.PrivateKey, id, session, writer string, start uint64) controlplane.AuditBatchEvidence {
	t.Helper()
	ev := testEvidence(t, priv, id, start, []receipt.Receipt{testActionReceipt(t, priv, id, receipt.ActionRead, "allow", "fetch", "url", "low")}, 0)
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(ev.Payload))
	if err != nil {
		t.Fatal(err)
	}
	prev := recorder.GenesisHash
	for i := range entries {
		entries[i].SessionID = session
		if writer != "" {
			entries[i].Version = 3
			entries[i].ChainKind = recorder.ChainKindRecorder
			entries[i].WriterInstanceID = writer
		}
		entries[i].PrevHash = prev
		entries[i].Hash = recorder.ComputeHash(entries[i])
		prev = entries[i].Hash
	}
	ev.Envelope.Chain.EntryVersion = entries[0].Version
	if writer != "" {
		ev.Envelope.Chain.SessionID = session
		ev.Envelope.Chain.ChainKind = recorder.ChainKindRecorder
		ev.Envelope.Chain.WriterInstanceID = writer
	}
	return resignNamespaceEvidence(t, priv, ev, entries)
}

func resignNamespaceEvidence(t *testing.T, priv ed25519.PrivateKey, ev controlplane.AuditBatchEvidence, entries []recorder.Entry) controlplane.AuditBatchEvidence {
	t.Helper()
	for i := range entries {
		entries[i].Detail = entries[i].RawDetail
	}
	ev.Payload = marshalTestEntries(t, entries)
	sum := sha256.Sum256(ev.Payload)
	ev.Envelope.PayloadSHA256 = hex.EncodeToString(sum[:])
	ev.Envelope.PayloadBytes = uint64(len(ev.Payload))
	ev.Envelope.Chain.SegmentHeadHash = entries[0].Hash
	ev.Envelope.Chain.SegmentTailHash = entries[len(entries)-1].Hash
	ev.Envelope.Chain.CheckpointHash = entries[len(entries)-1].Hash
	var err error
	ev.Envelope, err = auditbatcher.SignEnvelope(ev.Envelope, testAuditKeyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	ev.Summary.EnvelopeHash, err = ev.Envelope.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func namespaceOptions(t *testing.T, pub ed25519.PublicKey) Options {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Options{OrgID: testOrgID, FleetID: testFleetID, ReportID: "fixed-report", WindowStart: testWindowStart, WindowEnd: testWindowStart.Add(time.Hour), ConductorID: "conductor", Signer: priv, SignerKeyID: testReportKeyID, AuditKeys: staticAuditKeyResolver(pub), GeneratedAt: testWindowStart.Add(time.Minute)}
}

func TestBuildNamespacesPreserveWholeFleet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, v3 := range []bool{false, true} {
		t.Run(fmt.Sprintf("v3=%v", v3), func(t *testing.T) {
			var evidence []controlplane.AuditBatchEvidence
			for _, run := range []string{"run-a", "run-b"} {
				session, writer := run, ""
				if v3 {
					session = "run"
					writer = run
				}
				evidence = append(evidence, namespaceEvidence(t, priv, "batch-"+run, session, writer, 1))
			}
			// An independent follower remains part of the same complete fleet report.
			other := namespaceEvidence(t, priv, "batch-other", "run-a", "", 1)
			other.Envelope.InstanceID = "pl-2"
			entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(other.Payload))
			if err != nil {
				t.Fatal(err)
			}
			other = resignNamespaceEvidence(t, priv, other, entries)
			evidence = append(evidence, other)
			opts := namespaceOptions(t, pub)
			first, err := Build(t.Context(), staticEvidenceSource{evidence: evidence}, opts)
			if err != nil {
				t.Fatal(err)
			}
			slices.Reverse(evidence)
			second, err := Build(t.Context(), staticEvidenceSource{evidence: evidence}, opts)
			if err != nil {
				t.Fatal(err)
			}
			if first.Envelope.Payload != second.Envelope.Payload {
				t.Fatal("input order changed canonical report")
			}
			if first.Statement.PredicateType != fleetreceipt.PredicateTypeV2 || first.Statement.Predicate.SchemaVersion != 2 {
				t.Fatal("default is not v2")
			}
			p := first.Statement.Predicate
			if len(p.SourceBatches) != 3 || p.Summary.TotalActions != 3 || p.Summary.ByFollower[testInstanceID] != 2 || p.Summary.ByFollower["pl-2"] != 1 {
				t.Fatalf("incomplete fleet summary: %+v", p)
			}
			for i, b := range p.SourceBatches {
				if first.Statement.Subject[i].Name != sourceBatchSubjectName(b) || first.Statement.Subject[i].Digest.SHA256 != b.EnvelopeHash {
					t.Fatal("subjects not aligned")
				}
			}
			_, err = fleetreceipt.VerifyEnvelope(first.Envelope, map[string]ed25519.PublicKey{testReportKeyID: opts.Signer.Public().(ed25519.PublicKey)})
			if err != nil {
				t.Fatal(err)
			}
			opts.ReportVersion = 1
			if _, err := Build(t.Context(), staticEvidenceSource{evidence: evidence}, opts); err == nil || !strings.Contains(err.Error(), "overlap or are reordered") {
				t.Fatalf("v1 did not preserve refusal: %v", err)
			}
		})
	}
}

func TestBuildNamespaceRejectsSameRunAndUnknownVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := namespaceEvidence(t, priv, "a", "same", "", 1)
	b := namespaceEvidence(t, priv, "b", "same", "", 1)
	opts := namespaceOptions(t, pub)
	if _, err := Build(t.Context(), staticEvidenceSource{evidence: []controlplane.AuditBatchEvidence{a, b}}, opts); err == nil {
		t.Fatal("same run overlap accepted")
	}
	b = namespaceEvidence(t, priv, "b", "same", "", 3)
	for _, version := range []int{1, 2} {
		opts.ReportVersion = version
		if _, err := Build(t.Context(), staticEvidenceSource{evidence: []controlplane.AuditBatchEvidence{a, b}}, opts); err != nil {
			t.Fatalf("version %d refused adjacent same-namespace batches: %v", version, err)
		}
	}
	opts.ReportVersion = 99
	if _, err := Build(t.Context(), staticEvidenceSource{evidence: []controlplane.AuditBatchEvidence{a}}, opts); err == nil {
		t.Fatal("unknown report version accepted")
	}
}

func TestBuildNamespaceDerivesActualPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mixed session", "empty session", "bad hash", "checkpoint binding", "checkpoint signature", "unenrolled signer", "unsigned payload change"} {
		t.Run(name, func(t *testing.T) {
			ev := namespaceEvidence(t, priv, "payload-binding", "run", "", 1)
			entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(ev.Payload))
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "mixed session":
				entries[0].SessionID = "different"
				entries[0].Hash = recorder.ComputeHash(entries[0])
				entries[1].PrevHash = entries[0].Hash
				entries[1].Hash = recorder.ComputeHash(entries[1])
			case "empty session":
				for i := range entries {
					entries[i].SessionID = ""
					if i > 0 {
						entries[i].PrevHash = entries[i-1].Hash
					}
					entries[i].Hash = recorder.ComputeHash(entries[i])
				}
			case "bad hash":
				entries[0].Hash = strings.Repeat("a", 64)
				entries[1].PrevHash = entries[0].Hash
				entries[1].Hash = recorder.ComputeHash(entries[1])
			}
			ev = resignNamespaceEvidence(t, priv, ev, entries)
			if name == "checkpoint binding" || name == "checkpoint signature" {
				if name == "checkpoint binding" {
					ev.Envelope.Chain.CheckpointSeq = ev.Envelope.Chain.SeqStart
				} else {
					ev.Envelope.Chain.CheckpointSignature = conductorcore.SignaturePrefixEd25519 + strings.Repeat("3", 128)
				}
				ev.Envelope, err = auditbatcher.SignEnvelope(ev.Envelope, testAuditKeyID, priv)
				if err != nil {
					t.Fatal(err)
				}
				ev.Summary.EnvelopeHash, err = ev.Envelope.CanonicalHash()
				if err != nil {
					t.Fatal(err)
				}
			}
			opts := namespaceOptions(t, pub)
			if name == "unenrolled signer" {
				wrong, _, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				opts.AuditKeys = staticAuditKeyResolver(wrong)
			}
			if name == "unsigned payload change" {
				ev.Payload = append(ev.Payload, ' ')
			}
			if _, err := Build(t.Context(), staticEvidenceSource{evidence: []controlplane.AuditBatchEvidence{ev}}, opts); err == nil {
				t.Fatal("unverified namespace accepted")
			}
		})
	}
}

func TestDeriveNamespaceCancellation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := namespaceEvidence(t, priv, "cancel", "run", "", 1)
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(ev.Payload))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := deriveChainIdentity(ctx, ev.Envelope, entries); err == nil {
		t.Fatal("cancellation accepted")
	}
}
