// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
)

func TestFleetReportV2VerificationRemainsFree(t *testing.T) {
	t.Setenv("PIPELOCK_LICENSE_KEY", "")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := fleetReportStatementWithLimits([]string{fleetLimitL1NoReplay})
	s.PredicateType = fleetreceipt.PredicateTypeV2
	s.Predicate.SchemaVersion = 2
	s.Predicate.SourceBatches[0].Chain = &fleetreceipt.ChainIdentity{EntryVersion: 2, SessionID: "run-a"}
	env, err := fleetreceipt.SignStatement(s, "report-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := fleetreceipt.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fleet-v2.dsse.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	assertFleetPartial(t, verifyFleetReportWithOptions(&out, path, []string{hex.EncodeToString(pub)}, false, false))
	if !strings.Contains(out.String(), "FLEET RECEIPT VALID PREFIX, END UNPROVEN") || !strings.Contains(out.String(), fleetLimitL1NoReplay) {
		t.Fatal("missing assurance limits")
	}
	if !strings.Contains(out.String(), "cross_session_continuity_unproven (receiver observations unavailable)") {
		t.Fatal("archived v2 must display unavailable history")
	}
	s.Predicate.History = &fleetreceipt.History{
		Continuity: fleetreceipt.ContinuityUnproven,
		Sessions:   []fleetreceipt.ObservedChain{{InstanceID: s.Predicate.SourceBatches[0].InstanceID, Chain: *s.Predicate.SourceBatches[0].Chain, FirstReceived: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), LastReceived: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), SeqStart: s.Predicate.SourceBatches[0].SeqStart, SeqEnd: s.Predicate.SourceBatches[0].SeqEnd}},
		Gaps:       []fleetreceipt.SequenceGap{}, Retention: fleetreceipt.RetentionCoverage{HistoryUnknown: true, PrunedBefore: "2026-01-01T00:00:00Z"},
	}
	env, err = fleetreceipt.SignStatement(s, "report-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err = fleetreceipt.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	assertFleetPartial(t, verifyFleetReportWithOptions(&out, path, []string{hex.EncodeToString(pub)}, false, false))
	for _, fact := range []string{fleetreceipt.ContinuityUnproven, "Multiple sessions: false", "Sequence gaps:    0", "History unknown:  true", "Pruned before:    2026-01-01T00:00:00Z"} {
		if !strings.Contains(out.String(), fact) {
			t.Fatalf("missing signed history fact %q: %s", fact, out.String())
		}
	}
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFleetReportWithOptions(&out, path, []string{hex.EncodeToString(wrong)}, false, false); err == nil {
		t.Fatal("wrong key accepted")
	}
}
