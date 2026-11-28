// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
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

func TestVerifyReceiptCmd_LegacyDirWithLeftoverCutoverInventory(t *testing.T) {
	source := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "frozen", "v1", "action-receipt-v1-chain.jsonl")
	raw, err := os.ReadFile(filepath.Clean(source))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence-conformance-session-0.jsonl"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	inventoryName := v3.InventoryFilename(v3.Digest([]byte(`{"chains":[],"v":1}`)))
	if err := os.WriteFile(filepath.Join(dir, inventoryName), []byte(`{"chains":[],"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := VerifyReceiptCmd()
	cmd.SetArgs([]string{"--chain", dir, "--session", "conformance-session", "--allow-unpinned", "--allow-prefix"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatalf("legacy chain with leftover cutover inventory should verify on legacy path, got %v\n%s", err, out.String())
	}
}

func TestVerifyReceiptCmd_NestedV3ChainGuidance(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o750); err != nil {
		t.Fatal(err)
	}
	_, pub := testreceipt.V3(t, child, false)
	cmd := VerifyReceiptCmd()
	cmd.SetArgs([]string{"--chain", root, "--key", hex.EncodeToString(pub)})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.ExecuteContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt --chain "+child) {
		t.Fatalf("nested chain diagnostic = %v, want verifier guidance naming %s", err, child)
	}
}

// A root stream must not verify as VALID while a descendant receipt-profile
// file stays outside that verification. Nested-only roots already refuse;
// a claimed root used to return before descendant locations were discovered.
func TestVerifyReceiptCmd_ClaimedRootDoesNotHideNestedProfile(t *testing.T) {
	root := t.TempDir()
	_, pub := testreceipt.V3(t, root, false)
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, child, true)
	cmd := VerifyReceiptCmd()
	cmd.SetArgs([]string{"--chain", root, "--key", hex.EncodeToString(pub)})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.ExecuteContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt --chain "+child) {
		t.Fatalf("claimed root hid nested receipt-profile damage: %v", err)
	}
	var result v3.Result
	if json.Unmarshal(out.Bytes(), &result) == nil && result.Verdict == "VALID" && result.ExitCode == 0 {
		t.Fatal("verdict VALID over a tree with an unverified nested receipt profile")
	}
}

func TestVerifyReceiptCmd_ClaimedRootDoesNotHideDeeperNestedProfile(t *testing.T) {
	root := t.TempDir()
	_, pub := testreceipt.V3(t, root, false)
	leaf := filepath.Join(root, "mid", "leaf")
	if err := os.MkdirAll(leaf, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, leaf, true)
	cmd := VerifyReceiptCmd()
	cmd.SetArgs([]string{"--chain", root, "--key", hex.EncodeToString(pub)})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.ExecuteContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt --chain "+leaf) {
		t.Fatalf("claimed root hid a deeper nested receipt profile: %v", err)
	}
}
