// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package receiptinput_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// TestRecorderClaimMatchesV3ClaimsInput fails when the recorder, which cannot
// import the v3 package, stops agreeing with it about which directories belong
// to v3. A legacy write that lands in a directory the readers call v3 splits
// one evidence directory across two formats.
func TestRecorderClaimMatchesV3ClaimsInput(t *testing.T) {
	const stream = "11111111111111111111111111111111"
	v3Line := `{"payloadType":"application/vnd.pipelock.receipt.v3+json","payload":"e30="}` + "\n"
	legacyLine := `{"v":1,"type":"action_receipt"}` + "\n"
	hash := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"empty", nil},
		{"legacy shard", map[string]string{"evidence-proxy-0.jsonl": legacyLine}},
		{"v3 stream", map[string]string{stream + "-0000000000000000.receipt-v3.jsonl": v3Line}},
		{"empty v3 stream", map[string]string{stream + "-0000000000000000.receipt-v3.jsonl": ""}},
		{"future profile", map[string]string{stream + "-0000000000000000.receipt-v4.jsonl": ""}},
		{"long profile number", map[string]string{"s.receipt-v99999999999999999999.jsonl": ""}},
		{"malformed v3 name", map[string]string{"stream.receipt-v3.jsonl": ""}},
		{"uppercase stream", map[string]string{strings.ToUpper(stream) + "-0000000000000000.receipt-v3.jsonl": ""}},
		{"v3 under shard name", map[string]string{"evidence-proxy-0.jsonl": v3Line}},
		{"v3 under single dash shard name", map[string]string{"evidence-v3.jsonl": v3Line}},
		{"v3 under group artifact", map[string]string{"receipt-group-a.json": v3Line}},
		{"v3 under activation", map[string]string{"activation-receipts.jsonl": v3Line}},
		{"v3 under redaction", map[string]string{"redaction-receipts.jsonl": v3Line}},
		{"v3 under ratification", map[string]string{"ratification-receipts.jsonl": v3Line}},
		{"v3 under unrelated name", map[string]string{"notes.txt": v3Line}},
		{"cutover inventory only", map[string]string{"receipt-v3-cutover-" + hash + ".json": "{}"}},
		{"profile suffix only as a prefix", map[string]string{"x.receipt-v3.jsonl.bak": ""}},
		{"mixed", map[string]string{"evidence-proxy-0.jsonl": legacyLine, stream + "-0000000000000000.receipt-v3.jsonl": v3Line}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, data := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := v3.ClaimsInput(dir, true)
			if err != nil {
				t.Fatal(err)
			}
			ran := false
			err = recorder.WithEvidenceWriterCeremonyLock(dir, func() error {
				ran = true
				return nil
			})
			refused := errors.Is(err, recorder.ErrLegacyEvidenceFormat)
			if refused != want || ran == refused {
				t.Fatalf("v3.ClaimsInput = %t but recorder refused = %t (ran %t, err %v)", want, refused, ran, err)
			}
			if !refused && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestRecorderOwnsEveryV3EvidenceName keeps the output-collision guards honest:
// every name the v3 package claims or writes into an evidence directory is one
// the recorder reports as recorder-owned.
func TestRecorderOwnsEveryV3EvidenceName(t *testing.T) {
	const stream = "11111111111111111111111111111111"
	for _, name := range []string{
		stream + "-0000000000000000.receipt-v3.jsonl",
		stream + "-0000000000000000.receipt-v4.jsonl",
		"stream.receipt-v3.jsonl",
		v3.InventoryFilename("sha256:" + strings.Repeat("ab", 32)),
	} {
		if !recorder.IsRecorderOwnedFile(name) {
			t.Errorf("recorder.IsRecorderOwnedFile(%q) = false", name)
		}
	}
}
