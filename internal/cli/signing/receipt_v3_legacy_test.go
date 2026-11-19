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

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyReceiptV3LegacyShardParity(t *testing.T) {
	const session = "conformance-session"
	legacy, err := os.ReadFile(filepath.Join(legacyFixtureRoot, "frozen/v1/action-receipt-v1-chain.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	first, tail, _ := bytes.Cut(legacy, []byte{'\n'})
	second, afterSecond, _ := bytes.Cut(tail, []byte{'\n'})
	two := bytes.Join([][]byte{first, second, {}}, []byte{'\n'})
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
		{"overlapping shards", "1", two, tail, "CHAIN BROKEN"},
		{"second signed genesis", "1", append(bytes.Clone(first), '\n'), append(repeatedLine, '\n'), "CHAIN BROKEN"},
		{"missing position", "2", append(bytes.Clone(first), '\n'), afterSecond, "CHAIN BROKEN"},
		{"changed recorder hash", "2", two, bytes.Replace(afterSecond, []byte("receipt: allow"), []byte("receipt: block"), 1), "CHAIN BROKEN"},
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

			compareMixedLegacy(t, dir, session, []string{"--allow-unpinned", "--allow-prefix"}, tc.want)
		})
	}
}

const (
	legacyFixtureRoot = "../../../sdk/conformance/testdata"
	v3ParityOpener    = "11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl"
)

func TestVerifyReceiptV3LegacyEndProofFixtures(t *testing.T) {
	root := filepath.Join(legacyFixtureRoot, "end-proof")
	manifest, err := os.ReadFile(filepath.Clean(filepath.Join(root, "expect.json")))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Key   string
		Cases []struct {
			Name, File, Status string
			Flags              []string
		}
	}
	if err := json.Unmarshal(manifest, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			compareMixedLegacyFixture(t, filepath.Join(root, fixture.File),
				append([]string{"--key", fixtures.Key}, fixture.Flags...), fixture.Status)
		})
	}
}

func TestVerifyReceiptV3FrozenLegacyChains(t *testing.T) {
	root := filepath.Join(legacyFixtureRoot, "frozen/v1")
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range files {
		if filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			compareMixedLegacyFixture(t, filepath.Join(root, entry.Name()), []string{"--allow-unpinned", "--allow-prefix"}, "VALID PREFIX, END UNPROVEN")
		})
	}
}

func compareMixedLegacyFixture(t *testing.T, path string, flags []string, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := bytes.Cut(data, []byte{'\n'})
	entry, err := recorder.ParseEntryLine(head)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "evidence-"+entry.SessionID+"-0.jsonl")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	compareMixedLegacy(t, dir, entry.SessionID, flags, want)
}

func compareMixedLegacy(t *testing.T, dir, session string, flags []string, want string) {
	t.Helper()
	args := []string{"--chain", dir}
	if session != "" {
		args = append(args, "--session", session)
	}
	cmd := VerifyReceiptCmd()
	var old bytes.Buffer
	cmd.SetOut(&old)
	cmd.SetErr(&old)
	cmd.SetArgs(append(args, flags...))
	oldErr := cmd.ExecuteContext(t.Context())
	oldClass := "pass"
	if oldErr != nil {
		oldClass = "failure"
	}
	oldVerdict, _, _ := strings.Cut(old.String(), ":")
	if oldVerdict != want {
		t.Fatalf("legacy result %s, error %v, output %s", oldVerdict, oldErr, old.String())
	}

	expected := map[string]string{oldVerdict: oldClass}
	for _, label := range []string{"RESTART CONTINUITY FAILED", "RESTART CONTINUITY INCOMPLETE"} {
		if strings.Contains(old.String(), label+":") {
			expected[label] = "failure"
		}
	}
	rows := mixedLegacyResults(t, dir, flags...)
	for _, row := range rows {
		if expected[row.Verdict] != row.Class {
			t.Fatalf("mixed class %q label %q differs from legacy diagnostics %v", row.Class, row.Verdict, expected)
		}
		delete(expected, row.Verdict)
	}
	if len(expected) != 0 {
		t.Fatalf("mixed legacy rows %+v lack legacy diagnostics %v", rows, expected)
	}
}

func mixedLegacyResults(t *testing.T, dir string, flags ...string) []v3.LegacyResult {
	t.Helper()
	opener, err := os.ReadFile(filepath.Join(legacyFixtureRoot, "v3/g01-valid-line", v3ParityOpener))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, v3ParityOpener), opener, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := VerifyReceiptCmd()
	var mixed bytes.Buffer
	cmd.SetOut(&mixed)
	cmd.SetErr(&mixed)
	cmd.SetArgs(append([]string{"--chain", dir, "--json"}, flags...))
	_ = cmd.ExecuteContext(t.Context())
	var result struct {
		Legacy []v3.LegacyResult
	}
	dec := json.NewDecoder(bytes.NewReader(mixed.Bytes()))
	if err := dec.Decode(&result); err != nil {
		t.Fatalf("decode mixed result: %v, output %s", err, mixed.String())
	}
	return result.Legacy
}
