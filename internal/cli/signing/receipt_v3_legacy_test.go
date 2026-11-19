// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyReceiptV3LegacyShardParity(t *testing.T) {
	const (
		fixtures = "../../../sdk/conformance/testdata"
		session  = "conformance-session"
	)
	legacy, err := os.ReadFile(filepath.Join(fixtures, "frozen/v1/action-receipt-v1-chain.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	first, tail, _ := bytes.Cut(legacy, []byte{'\n'})
	second, afterSecond, _ := bytes.Cut(tail, []byte{'\n'})
	two := bytes.Join([][]byte{first, second, {}}, []byte{'\n'})
	opener := filepath.Join(fixtures, "v3/g01-valid-line/11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl")
	v3Bytes, err := os.ReadFile(filepath.Clean(opener))
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := recorder.ParseEntryLine(first)
	if err != nil {
		t.Fatal(err)
	}
	repeated.PrevHash = repeated.Hash
	repeated.Sequence++
	repeated.Hash = recorder.ComputeHash(repeated)
	repeatedLine, err := json.Marshal(repeated)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, rightStart string
		left, right      []byte
		want             string
	}{
		{"complete split", "2", two, afterSecond, "VALID PREFIX, END UNPROVEN"},
		{"overlapping shards", "1", two, tail, "INVALID"},
		{"second signed genesis", "1", append(bytes.Clone(first), '\n'), append(repeatedLine, '\n'), "INVALID"},
		{"missing position", "2", append(bytes.Clone(first), '\n'), afterSecond, "INVALID"},
		{"changed recorder hash", "2", two, bytes.Replace(afterSecond, []byte("receipt: allow"), []byte("receipt: block"), 1), "INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name string, data []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write("evidence-"+session+"-0.jsonl", tc.left)
			write("evidence-"+session+"-"+tc.rightStart+".jsonl", tc.right)

			cmd := VerifyReceiptCmd()
			var old bytes.Buffer
			cmd.SetOut(&old)
			cmd.SetErr(&old)
			cmd.SetArgs([]string{"--chain", dir, "--session", session, "--allow-unpinned", "--allow-prefix"})
			oldErr := cmd.ExecuteContext(t.Context())
			oldVerdict := "INVALID"
			if oldErr == nil && strings.Contains(old.String(), "VALID PREFIX, END UNPROVEN") {
				oldVerdict = "VALID PREFIX, END UNPROVEN"
			}
			if oldVerdict != tc.want {
				t.Fatalf("legacy result %s, error %v, output %s", oldVerdict, oldErr, old.String())
			}

			write(filepath.Base(opener), v3Bytes)
			cmd = VerifyReceiptCmd()
			var mixed bytes.Buffer
			cmd.SetOut(&mixed)
			cmd.SetErr(&mixed)
			cmd.SetArgs([]string{"--chain", dir, "--allow-unpinned", "--allow-prefix", "--json"})
			_ = cmd.ExecuteContext(t.Context())
			var result struct {
				Legacy   []struct{ Verdict string }
				Findings []struct{ Code string }
			}
			dec := json.NewDecoder(bytes.NewReader(mixed.Bytes()))
			if err := dec.Decode(&result); err != nil {
				t.Fatalf("decode mixed result: %v, output %s", err, mixed.String())
			}
			mixedVerdict := ""
			if len(result.Legacy) == 1 {
				mixedVerdict = result.Legacy[0].Verdict
			}
			for _, finding := range result.Findings {
				if finding.Code == "LEGACY_INVALID" {
					mixedVerdict = "INVALID"
				}
			}
			if mixedVerdict != oldVerdict {
				t.Fatalf("mixed verdict %q differs from legacy verdict %q: %s", mixedVerdict, oldVerdict, mixed.String())
			}
		})
	}
}
