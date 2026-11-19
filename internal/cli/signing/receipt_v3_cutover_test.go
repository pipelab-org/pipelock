// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
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

	writeOperationalRecord(t, dir, private)

	if out, err := run(base); err == nil || !strings.Contains(out, "LEGACY_INVALID") {
		t.Fatalf("mixed directory lost the legacy trust requirement: %v\n%s", err, out)
	}
	if out, err := run(withEndorsement); err != nil || !strings.Contains(out, "VALID PREFIX, END UNPROVEN") {
		t.Fatalf("mixed directory endorsed verification: %v\n%s", err, out)
	}
}

func TestVerifyReceiptCmd_V3WithSeparateOperationalRecorder(t *testing.T) {
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	writeOperationalRecord(t, dir, key)
	writer, err := v3.OpenStreamWriter(t.Context(), v3.StreamWriterOptions{
		Dir: dir, SigningKey: key, PolicyHash: v3.Digest(nil),
		Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "1"},
		Coverage: v3.Coverage{RedactionRuleset: v3.Ruleset{Hash: v3.Digest(nil), ID: "example", Version: "1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	cmd := VerifyReceiptCmd()
	cmd.SetArgs([]string{"--chain", dir, "--key", hex.EncodeToString(key.Public().(ed25519.PublicKey))})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.ExecuteContext(t.Context()); err != nil || !strings.Contains(out.String(), "\"verdict\":\"VALID\"") {
		t.Fatalf("verification missed the v3 evidence root: %v\n%s", err, out.String())
	}
}

func writeOperationalRecord(t *testing.T, dir string, key ed25519.PrivateKey) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Dir: filepath.Join(dir, "operational"), Enabled: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if err := rec.Record(recorder.Entry{Type: "decision", SessionID: "example"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
}
