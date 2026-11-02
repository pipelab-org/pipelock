// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
)

var updateAARPEndProof = flag.Bool("update-aarp-end-proof", false, "regenerate the AARP endpoint corpus")

// The existing signed AARP stream supplies the source evidence. Endpoint
// expectations are independent caller inputs, never inferred by the CLI.
func TestGenerateAARPEndProofCorpus(t *testing.T) {
	if !*updateAARPEndProof {
		t.Skip("pass -update-aarp-end-proof")
	}
	dir := "testdata/aarp-end-proof"
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	data := readFixture(t, filepath.Join(aarpCorpusDir, "chain/c01-valid-stream.aarp.jsonl"))
	envs, err := parseChainLines(data)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	write("stream.jsonl", data)
	write("tail.jsonl", append(bytes.Join(lines[:len(lines)-1], []byte("\n")), '\n'))
	write("head.jsonl", append(bytes.Join(lines[1:], []byte("\n")), '\n'))
	forged := append([]byte(nil), data...)
	sig := []byte(envs[0].Signatures[0].Sig)
	replacement := append([]byte(nil), sig...)
	if replacement[len("ed25519:")] == 'A' {
		replacement[len("ed25519:")] = 'B'
	} else {
		replacement[len("ed25519:")] = 'A'
	}
	forged = bytes.Replace(forged, sig, replacement, 1)
	write("signature.jsonl", forged)
	// Parallel signatures are independent: a bad one beside an authenticated
	// one must not hide the latter or inflate its claim.
	var parallel bytes.Buffer
	for i, env := range envs {
		if i == 0 {
			bad := env.Signatures[0]
			bad.Sig = string(replacement)
			env.Signatures = append([]aarp.Signature{bad}, env.Signatures...)
		}
		encoded, err := aarp.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = parallel.Write(encoded)
		_ = parallel.WriteByte('\n')
	}
	write("parallel.jsonl", parallel.Bytes())
	head, err := envs[len(envs)-1].PayloadDigest()
	if err != nil {
		t.Fatal(err)
	}
	seq := envs[len(envs)-1].Chain.Seq
	corpus := struct {
		Trust string         `json:"trust"`
		Cases []endProofCase `json:"cases"`
	}{"../aarp-corpus/trust.json", []endProofCase{
		{"unbounded", "stream.jsonl", []string{}, 3, endProofPrefix, false},
		{"tail", "tail.jsonl", []string{}, 3, endProofPrefix, false},
		{"head", "head.jsonl", []string{}, 1, "CHAIN BROKEN", false},
		{"signature", "signature.jsonl", []string{}, 1, "CHAIN BROKEN", false},
		{"allow-prefix", "tail.jsonl", []string{"--allow-prefix"}, 0, endProofPrefix, false},
		{"pinned-head", "stream.jsonl", []string{"--expect-head", head}, 0, "CHAIN VALID", true},
		{"pinned-seq", "stream.jsonl", []string{"--expect-seq", seq}, 0, "CHAIN VALID", true},
		{"tail-pinned-head", "tail.jsonl", []string{"--expect-head", head}, 1, "CHAIN BROKEN", false},
		{"tail-pinned-seq", "tail.jsonl", []string{"--expect-seq", seq}, 1, "CHAIN BROKEN", false},
		{"pin-mismatch-allow-prefix", "tail.jsonl", []string{"--expect-head", head, "--allow-prefix"}, 1, "CHAIN BROKEN", false},
		{"head-allow-prefix", "head.jsonl", []string{"--allow-prefix"}, 1, "CHAIN BROKEN", false},
		{"signature-allow-prefix", "signature.jsonl", []string{"--allow-prefix"}, 1, "CHAIN BROKEN", false},
		{"parallel-signatures", "parallel.jsonl", []string{"--expect-seq", seq}, 0, "CHAIN VALID", true},
	}}
	body, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write("expect.json", append(body, '\n'))
}
