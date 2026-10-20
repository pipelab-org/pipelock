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

	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
)

func TestFleetReportV2VerificationRemainsFree(t *testing.T) {
	t.Setenv("PIPELOCK_LICENSE_KEY", "")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := fleetReportStatementWithLimits("L1", []string{fleetLimitL1NoReplay})
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
	if err := verifyFleetReportWithOptions(&out, path, []string{hex.EncodeToString(pub)}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "FLEET RECEIPT OK") || !strings.Contains(out.String(), fleetLimitL1NoReplay) {
		t.Fatal("missing assurance limits")
	}
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFleetReportWithOptions(&out, path, []string{hex.EncodeToString(wrong)}, false); err == nil {
		t.Fatal("wrong key accepted")
	}
}
