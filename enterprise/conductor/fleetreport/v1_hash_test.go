//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleetreport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestBuildV1RefusesSignedBatchWithInvalidRecorderHash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := namespaceEvidence(t, priv, "valid-hash", "run-a", "", 1)
	opts := namespaceOptions(t, pub)
	opts.ReportVersion = fleetreceipt.SchemaVersionV1
	if _, err := Build(t.Context(), staticEvidenceSource{evidence: []controlplane.AuditBatchEvidence{valid}}, opts); err != nil {
		t.Fatalf("valid single-run batch refused: %v", err)
	}

	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(valid.Payload))
	if err != nil {
		t.Fatal(err)
	}
	entries[0].Summary += "-altered"
	if recorder.ComputeHash(entries[0]) == entries[0].Hash {
		t.Fatal("mutation did not invalidate recorder hash")
	}
	bad := resignNamespaceEvidence(t, priv, valid, entries)
	if err := conductorcore.ValidateAuditSegment(bad.Envelope.Chain, entries); err != nil {
		t.Fatalf("segment-local checks unexpectedly rejected fixture: %v", err)
	}
	if _, err := Build(t.Context(), staticEvidenceSource{evidence: []controlplane.AuditBatchEvidence{bad}}, opts); err == nil || !strings.Contains(err.Error(), "recorder hash mismatch") {
		t.Fatalf("v1 signed report did not refuse invalid recorder hash: %v", err)
	}
}
