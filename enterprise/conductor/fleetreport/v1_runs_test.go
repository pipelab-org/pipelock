//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleetreport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
)

// V1 has no field for chain identity or the continuity limit, so a v1 report
// must refuse a window holding more than one recorder run for a follower
// rather than sign them as one sequence. Receivers now admit a restarted run,
// so this window is reachable without any pruning.
func TestBuildV1RefusesMultipleRecorderRuns(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		evidence []controlplane.AuditBatchEvidence
		// v2 groups each run separately: it records multiple sessions,
		// accepts one session with several writers, and refuses a batch whose
		// run it can't establish.
		v2MultipleSessions bool
		v2Refuses          bool
	}{
		{
			// Ranges don't overlap, so the v1 overlap check alone accepts this.
			name: "restarted session below earlier run",
			evidence: []controlplane.AuditBatchEvidence{
				namespaceEvidence(t, priv, "batch-run-b", "run-b", "", 1),
				namespaceEvidence(t, priv, "batch-run-a-late", "run-a", "", 50),
			},
			v2MultipleSessions: true,
		},
		{
			name: "same session with two v3 writers",
			evidence: []controlplane.AuditBatchEvidence{
				namespaceEvidence(t, priv, "batch-writer-a", "run-a", "writer-a", 1),
				namespaceEvidence(t, priv, "batch-writer-b", "run-a", "writer-b", 50),
			},
		},
		{
			name: "legacy and session-bearing recorder",
			evidence: []controlplane.AuditBatchEvidence{
				namespaceEvidence(t, priv, "batch-legacy", "", "", 1),
				namespaceEvidence(t, priv, "batch-session", "run-a", "", 50),
			},
			v2Refuses: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := namespaceOptions(t, pub)
			opts.ReportVersion = fleetreceipt.SchemaVersionV1
			_, err := Build(t.Context(), staticEvidenceSource{evidence: tc.evidence}, opts)
			if !errors.Is(err, ErrV1MultipleRuns) {
				t.Fatalf("v1 Build err = %v, want ErrV1MultipleRuns", err)
			}
			if !strings.Contains(err.Error(), "--report-version 2") {
				t.Fatalf("v1 refusal %q does not name the v2 remedy", err)
			}

			opts.ReportVersion = fleetreceipt.SchemaVersionV2
			v2, err := Build(t.Context(), staticEvidenceSource{evidence: tc.evidence}, opts)
			if tc.v2Refuses {
				if err == nil {
					t.Fatal("v2 Build accepted a batch without an established run")
				}
				return
			}
			if err != nil {
				t.Fatalf("v2 Build refused the same window: %v", err)
			}
			if got := v2.Statement.Predicate.History.MultipleSessions; got != tc.v2MultipleSessions {
				t.Fatalf("v2 multipleSessions = %t, want %t", got, tc.v2MultipleSessions)
			}
		})
	}
}

func TestBuildV1AcceptsOneRecorderRun(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evidence := []controlplane.AuditBatchEvidence{
		namespaceEvidence(t, priv, "batch-run-a-early", "run-a", "", 1),
		namespaceEvidence(t, priv, "batch-run-a-late", "run-a", "", 50),
	}
	opts := namespaceOptions(t, pub)
	opts.ReportVersion = fleetreceipt.SchemaVersionV1
	result, err := Build(t.Context(), staticEvidenceSource{evidence: evidence}, opts)
	if err != nil {
		t.Fatalf("v1 Build refused one recorder run: %v", err)
	}
	if got := result.Statement.Predicate.SchemaVersion; got != fleetreceipt.SchemaVersionV1 {
		t.Fatalf("schema version = %d, want 1", got)
	}
	if _, err := fleetreceipt.VerifyEnvelope(result.Envelope, map[string]ed25519.PublicKey{testReportKeyID: opts.Signer.Public().(ed25519.PublicKey)}); err != nil {
		t.Fatalf("v1 report over one run does not verify: %v", err)
	}
}
