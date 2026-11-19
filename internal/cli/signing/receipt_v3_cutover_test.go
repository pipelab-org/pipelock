// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func TestVerifyReceiptCmd_EndorsedRotationSurvivesCutover(t *testing.T) {
	dir, root, private, successor, endorsement := buildEndorsedRotatedChainJSONLKeys(t, true)
	base := []string{"--chain", dir, "--key", hex.EncodeToString(root), "--session", "proxy", "--allow-prefix"}
	run := func(args []string) (string, error) {
		cmd := VerifyReceiptCmd()
		cmd.SetArgs(args)
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		err := cmd.ExecuteContext(t.Context())
		return out.String(), err
	}
	withEndorsement := append(append([]string{}, base...), "--rotation-endorsement", endorsement)
	if out, err := run(withEndorsement); err != nil {
		t.Fatalf("legacy endorsed verification: %v\n%s", err, out)
	}
	writer, err := v3.OpenStreamWriter(t.Context(), v3.StreamWriterOptions{
		Dir: dir, SigningKey: private, PriorSignerKeys: []ed25519.PublicKey{successor.Public().(ed25519.PublicKey)},
		Identity:   v3.Writer{Instance: "example", Product: "example", Version: "1"},
		PolicyHash: v3.Digest(nil),
		Coverage:   v3.Coverage{RedactionRuleset: v3.Ruleset{Hash: v3.Digest(nil), ID: "example", Version: "1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}

	if out, err := run(base); err == nil || !strings.Contains(out, "LEGACY_INVALID") {
		t.Fatalf("mixed directory lost the legacy trust requirement: %v\n%s", err, out)
	}
	if out, err := run(withEndorsement); err != nil || !strings.Contains(out, "VALID PREFIX, END UNPROVEN") {
		t.Fatalf("mixed directory endorsed verification: %v\n%s", err, out)
	}
}
