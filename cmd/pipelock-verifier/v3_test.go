// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStandaloneV3Contract(t *testing.T) {
	const name = "11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl"
	vector := filepath.Join("..", "..", "sdk", "conformance", "testdata", "v3", "g01-valid-line")
	input := filepath.Join(vector, name)
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(vector, "request.json")))
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file, err := os.ReadFile(filepath.Clean(input))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), file, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(t.TempDir(), "bare.jsonl")
	if err := os.WriteFile(legacy, []byte("malformed legacy input\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want, stderr string
		args               []string
		status             int
	}{
		{"projection", "projection.json", "", []string{"--output", "projection", "--key", request.Keys[0], input}, 0},
		{"default result", "expect.json", "", []string{"--key", request.Keys[0], input}, 0},
		{"directory", "projection.json", "", []string{"--key", request.Keys[0], "--output", "projection", dir}, 0},
		{"recognized filename", "true\n", "", []string{"--claims", input}, 0},
		{"empty evidence", "", "", nil, 3},
		{"expected stream head", "", "", []string{"--key", request.Keys[0], "--expect-head", strings.Repeat("1", 32) + ":1:" +
			"sha256:4cfd86711ab5204b8df80214f3100f49e110135adfa85ccd32894ddc4d97d9fe", input}, 0},
		{"expected stream seq", "", "", []string{"--key", request.Keys[0], "--expect-seq", strings.Repeat("1", 32) + ":1", input}, 0},
		{"unknown flag", "", "unknown flag", []string{"--wrong"}, 2},
		{"claims no file", "", "--claims requires one file", []string{"--claims"}, 2},
		{"claims with output", "", "--claims requires one file", []string{"--claims", "--output", "result", input}, 2},
		{"claims missing file", "", "resolve evidence path", []string{"--claims", filepath.Join(dir, "missing.receipt-v3.jsonl")}, 2},
		{"legacy-only input", "", "legacy-only evidence", []string{legacy}, 2},
		{"missing file", "", "stat evidence input", []string{filepath.Join(dir, "missing")}, 2},
		{"specified directory among files", "", "open evidence", []string{input, dir}, 2},
		{"bad output", "", "output must be", []string{"--output", "bad", input}, 2},
		{"bad format", "", "format must be v3", []string{"--format", "", input}, 2},
		{"format with multiple paths", "", "requires exactly one file", []string{"--format", "v3", input, input}, 2},
		{"format with directory", "", "only to a single file", []string{"--format", "v3", dir}, 2},
		{"invalid key", "", "lowercase hexadecimal", []string{"--key", strings.ToUpper(request.Keys[0]), input}, 2},
		{"invalid hex key", "", "decode public key", []string{"--key", strings.Repeat("z", 64), input}, 2},
		{"invalid lineage", "", "expected lineage", []string{"--expect-lineage", "bad", input}, 2},
		{"invalid expected seq", "", "expected sequence", []string{"--expect-seq", "bad", input}, 2},
		{"invalid expected head", "", "expected head", []string{"--expect-head", "bad", input}, 2},
		{"invalid accepted discontinuity", "", "accepted discontinuity", []string{"--accept-discontinuity", "bad", input}, 2},
		{"invalid partial history stream", "", "partial history must name", []string{"--allow-partial-history", "bad", input}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			code := execute(append([]string{"v3"}, tc.args...), &out, &stderr)
			if code != tc.status {
				t.Fatalf("exit %d, want %d, output: %s, stderr: %s", code, tc.status, out.String(), stderr.String())
			}
			if tc.stderr != "" {
				if out.Len() != 0 || !strings.Contains(stderr.String(), tc.stderr) || strings.Count(stderr.String(), "\n") != 1 {
					t.Fatalf("expected one diagnostic containing %q, output: %s, stderr: %s", tc.stderr, out.String(), stderr.String())
				}
				return
			}
			if stderr.Len() != 0 || out.Len() == 0 {
				t.Fatalf("expected document only, output: %s, stderr: %s", out.String(), stderr.String())
			}
			want := []byte(tc.want)
			if strings.HasSuffix(tc.want, ".json") {
				fixture, err := os.ReadFile(filepath.Clean(filepath.Join(vector, tc.want)))
				if err != nil {
					t.Fatal(err)
				}
				want = fixture
			}
			if len(want) != 0 && !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("document differs from %q: %s", tc.want, out.String())
			}
		})
	}
}

type v3WriteFailure struct{}

func (v3WriteFailure) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestStandaloneV3OutputFailure(t *testing.T) {
	for _, args := range [][]string{{"v3"}, {"v3", "--claims", "testdata"}} {
		var stderr bytes.Buffer
		if len(args) > 1 {
			args[2] = filepath.Join(t.TempDir(), "named.receipt-v3.jsonl")
			if err := os.WriteFile(args[2], nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if code := execute(args, v3WriteFailure{}, &stderr); code != 2 || !strings.Contains(stderr.String(), "output unavailable") {
			t.Fatalf("exit %d, stderr %s", code, stderr.String())
		}
	}
}
