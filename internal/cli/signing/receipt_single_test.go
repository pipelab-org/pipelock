// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestVerifyReceiptCmdSingleEvidenceReceipt(t *testing.T) {
	dir := filepath.Join(parityClassesDir, "v2-only-shard")
	shards, err := filepath.Glob(filepath.Join(dir, "*-0.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("locate frozen receipt fixture: shards=%v err=%v", shards, err)
	}
	shard, err := os.ReadFile(filepath.Clean(shards[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Extract exact receipt bytes at a non-genesis position. Single-receipt
	// verification must work without the preceding receipt.
	var valid []byte
	for _, line := range bytes.Split(bytes.TrimSpace(shard), []byte("\n")) {
		var entry struct {
			Type   string          `json:"type"`
			Detail json.RawMessage `json:"detail"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Type == "evidence_receipt" {
			valid = entry.Detail
		}
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatalf("decode frozen receipt envelope: %v", err)
	}
	if string(envelope["chain_seq"]) != "1" {
		t.Fatalf("expected a frozen receipt at sequence 1, got %s", envelope["chain_seq"])
	}
	var proof map[string]json.RawMessage
	if err := json.Unmarshal(envelope["signature"], &proof); err != nil {
		t.Fatal(err)
	}
	proof["signature"] = json.RawMessage(`"ed25519:` + strings.Repeat("0", 2*ed25519.SignatureSize) + `"`)
	forgedProof, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(field string, raw json.RawMessage) []byte {
		t.Helper()
		altered := maps.Clone(envelope)
		if raw == nil {
			delete(altered, field)
		} else {
			altered[field] = raw
		}
		data, err := json.Marshal(altered)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	pinned := []string{"--key", filepath.Join(dir, "signer-key.hex")}
	unpinned := []string{"--allow-unpinned"}
	tests := []struct {
		name       string
		data       []byte
		flags      []string
		wantStatus string
		wantErr    string
	}{
		{name: "pinned", data: valid, flags: pinned, wantStatus: "OK:"},
		{name: "unpinned opt in", data: valid, flags: unpinned, wantStatus: "UNPINNED:"},
		{name: "unpinned default", data: valid, wantStatus: "UNPINNED:", wantErr: "verification unpinned"},
		{
			name: "explicit pin never falls back or uses later keys",
			data: valid,
			flags: []string{
				"--key", strings.Repeat("0", 2*ed25519.PublicKeySize),
				pinned[0], pinned[1], unpinned[0],
			},
			wantStatus: "FAILED:", wantErr: "is not in the trusted key set",
		},
		{
			name: "forged signature", data: mutate("signature", forgedProof), flags: unpinned,
			wantStatus: "FAILED:", wantErr: "signature verification failed",
		},
		{
			name: "tampered signed field", data: mutate("event_id", json.RawMessage(`"changed-event-id"`)), flags: pinned,
			wantStatus: "FAILED:", wantErr: "signature verification failed",
		},
		{
			name: "malformed JSON", data: []byte(`{"record_type": nope}`), flags: unpinned,
			wantErr: "invalid receipt JSON",
		},
		{
			name: "unknown record type", data: mutate("record_type", json.RawMessage(`"unknown"`)), flags: unpinned,
			wantErr: "unsupported receipt record_type",
		},
		{
			name: "both format discriminators", data: mutate("version", json.RawMessage(`1`)), flags: unpinned,
			wantErr: "ambiguous receipt format",
		},
		{
			name: "truncated file", data: valid[:len(valid)-1], flags: unpinned,
			wantErr: "invalid receipt JSON",
		},
		{
			name: "missing format discriminators", data: []byte(`{}`), flags: unpinned,
			wantErr: "missing receipt format discriminator",
		},
		{
			name: "non-string record type", data: mutate("record_type", json.RawMessage(`true`)), flags: unpinned,
			wantErr: "receipt record_type must be a string",
		},
		{
			name: "null record type", data: mutate("record_type", json.RawMessage(`null`)), flags: unpinned,
			wantErr: "receipt record_type must be a string",
		},
		{
			name: "missing v2 receipt version", data: mutate("receipt_version", nil), flags: unpinned,
			wantErr: "EvidenceReceipt v2 requires receipt_version",
		},
		{
			name: "wrong v2 receipt version", data: mutate("receipt_version", json.RawMessage(`1`)), flags: unpinned,
			wantStatus: "FAILED:", wantErr: "receipt_version",
		},
		{
			name: "non-integer v1 version", data: []byte(`{"version":"1"}`), flags: unpinned,
			wantErr: "receipt version must be an integer",
		},
		{
			name: "unsupported v1 version", data: []byte(`{"version":2}`), flags: unpinned,
			wantErr: "unsupported receipt version 2",
		},
		{
			name: "duplicate format discriminator",
			data: append([]byte(`{"record_type":"unknown",`), valid[1:]...), flags: unpinned,
			wantErr: "parsing evidence receipt",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "receipt.json")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := executeReceiptCommand(t, &out, append([]string{path}, tc.flags...)...)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verify receipt: %v\n%s", err, &out)
				}
			} else if err == nil || cliutil.ExitCodeOf(err) != 1 || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verify receipt error = %v, want exit 1 with %q\n%s", err, tc.wantErr, &out)
			}
			if tc.wantStatus == "" {
				if out.Len() != 0 {
					t.Fatalf("unparsed receipt produced output: %q", &out)
				}
				return
			}
			if !strings.HasPrefix(out.String(), tc.wantStatus+" "+path) {
				t.Fatalf("verify receipt output = %q, want %s %s", &out, tc.wantStatus, path)
			}
			if tc.wantStatus == "FAILED:" {
				return
			}
			if got, want := strings.Contains(out.String(), unpinnedReceiptBanner), tc.wantStatus == "UNPINNED:"; got != want {
				t.Fatalf("verify receipt output = %q, want unpinned banner=%t", &out, want)
			}
			for _, detail := range []string{"Payload kind: proxy_decision", "Chain seq:   1", "Chain continuity and completeness are unverified."} {
				if !strings.Contains(out.String(), detail) {
					t.Errorf("verify receipt output = %q, want %q", &out, detail)
				}
			}
		})
	}
}

func TestVerifyReceiptCmdSingleFileCompatibility(t *testing.T) {
	v1Path, v1Key := writeReceiptFailureFixture(t)
	dir := filepath.Join(parityClassesDir, "v2-only-shard")
	tests := []struct {
		name     string
		args     []string
		wantText []string
	}{
		{
			name: "v1 single file",
			args: []string{v1Path, "--key", v1Key},
			wantText: []string{
				"OK: " + v1Path, "Action ID:", "Action Type: read", "Verdict:     block",
				"Target:      https://api.vendor.example/data", "Signer:      " + v1Key,
				"Chain seq:   0", "Containment: UNKNOWN",
			},
		},
		{
			name: "chain directory",
			args: []string{"--chain", dir, "--allow-unpinned", "--allow-prefix"},
			wantText: []string{
				"CHAIN UNPINNED:", "Evidence receipts: 2", "RESTART CONTINUITY OK:", "VALID PREFIX, END UNPROVEN",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := executeReceiptCommand(t, &out, tc.args...); err != nil {
				t.Fatalf("verify receipt: %v\n%s", err, &out)
			}
			for _, want := range tc.wantText {
				if !strings.Contains(out.String(), want) {
					t.Errorf("verify receipt output = %q, want %q", &out, want)
				}
			}
		})
	}
}
