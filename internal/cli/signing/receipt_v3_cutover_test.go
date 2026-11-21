// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func TestVerifyReceiptCmd_RelativeMixedDirectory(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "v3", "g09-rotation-match")
	dir := t.TempDir()
	fixtures := os.DirFS(fixture)
	files, err := fs.ReadDir(fixtures, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := file.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasPrefix(name, "receipt-v3-cutover-") {
			continue
		}
		data, err := fs.ReadFile(fixtures, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	operational := filepath.Join(dir, "operational")
	if err := os.Mkdir(operational, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(operational, "evidence-example-0.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	requestBytes, err := fs.ReadFile(fixtures, "request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(requestBytes, &request); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Dir(dir))
	cmd := VerifyReceiptCmd()
	args := []string{"--chain", filepath.Base(dir), "--allow-prefix"}
	for _, key := range request.Keys {
		args = append(args, "--key", key)
	}
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.ExecuteContext(t.Context()); err != nil || !strings.Contains(out.String(), "VALID PREFIX, END UNPROVEN") {
		t.Fatalf("relative mixed directory: %v\n%s", err, out.String())
	}
	const session = "missing-session"
	cmd = VerifyReceiptCmd()
	cmd.SetArgs(append(args, "--session", session))
	cmd.SilenceUsage = true
	out.Reset()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	err = cmd.ExecuteContext(t.Context())
	var result v3.Result
	if decodeErr := json.Unmarshal(out.Bytes(), &result); decodeErr != nil {
		t.Fatalf("decode result: %v, command error: %v, output: %s", decodeErr, err, &out)
	}
	if err == nil || err.Error() != "INVALID" || result.Verdict != "INVALID" || result.ExitCode != 1 || len(result.Accepted) != 1 || result.Accepted[0] != (v3.Acceptance{Kind: "allow-prefix", Value: "true"}) {
		t.Fatalf("missing session: %v, verdict %q, exit %d, accepted %+v", err, result.Verdict, result.ExitCode, result.Accepted)
	}
	for _, finding := range result.Findings {
		if finding.Code == "EXPECTATION_NOT_MET" {
			return
		}
	}
	t.Fatalf("missing session did not fail its expectation: %+v", result.Findings)
}
