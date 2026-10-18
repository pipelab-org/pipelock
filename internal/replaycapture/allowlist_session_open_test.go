// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// safeSessionOpenRecord returns a session_open control record the allowlist
// accepts. Negative rows mutate exactly one field.
func safeSessionOpenRecord() receipt.ActionRecord {
	nonce := strings.Repeat("a1", 16)
	genesis := "g1:" + strings.Repeat("b2", 32)
	ar := safeBaseRecord()
	ar.Target = "pipelock://session/open"
	ar.RunNonce = nonce
	ar.ChainSeq = 0
	ar.ChainPrevHash = genesis
	ar.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlOpen,
		Open: &receipt.SessionOpen{
			RunNonce:        nonce,
			OpenNonce:       strings.Repeat("c3", 16),
			RecorderSession: "proxy",
			PolicyHash:      policyHashLabelPrefix + "abc",
			SignerKeyEpoch:  strings.Repeat("d4", 32),
			ChainOpenSeq:    0,
			GenesisHash:     genesis,
		},
	}
	return ar
}

func TestValidateReceiptPublicSafe_SessionOpenFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(ar *receipt.ActionRecord)
		wantMsg string // empty means the record must pass
	}{
		{name: "positive control", mutate: func(*receipt.ActionRecord) {}},
		{
			name:    "wrong control target",
			mutate:  func(ar *receipt.ActionRecord) { ar.Target = "pipelock://session/close" },
			wantMsg: "is not the expected control target",
		},
		{
			name:    "wrong kind",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Kind = receipt.SessionControlClose },
			wantMsg: "only session_open control receipts are public-safe",
		},
		{
			name:    "missing open body",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open = nil },
			wantMsg: "only session_open control receipts are public-safe",
		},
		{
			name: "heartbeat body present",
			mutate: func(ar *receipt.ActionRecord) {
				ar.SessionControl.Heartbeat = &receipt.SessionHeartbeat{}
			},
			wantMsg: "only session_open control receipts are public-safe",
		},
		{
			name:    "close body present",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Close = &receipt.SessionClose{} },
			wantMsg: "only session_open control receipts are public-safe",
		},
		{
			name: "empty run nonce",
			mutate: func(ar *receipt.ActionRecord) {
				ar.RunNonce = ""
				ar.SessionControl.Open.RunNonce = ""
			},
			wantMsg: "run_nonce is not the expected nonce shape",
		},
		{
			name:    "run nonce mismatch",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.RunNonce = strings.Repeat("e5", 16) },
			wantMsg: "run_nonce is not the expected nonce shape",
		},
		{
			name: "run nonce bad shape",
			mutate: func(ar *receipt.ActionRecord) {
				ar.RunNonce = strings.Repeat("Z", 32)
				ar.SessionControl.Open.RunNonce = ar.RunNonce
			},
			wantMsg: "run_nonce is not the expected nonce shape",
		},
		{
			name: "run nonce one hex short",
			mutate: func(ar *receipt.ActionRecord) {
				ar.RunNonce = strings.Repeat("a", 31)
				ar.SessionControl.Open.RunNonce = ar.RunNonce
			},
			wantMsg: "run_nonce is not the expected nonce shape",
		},
		{
			name:    "open nonce bad shape",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.OpenNonce = "short" },
			wantMsg: "open_nonce is not the expected nonce shape",
		},
		{
			name:    "open nonce one hex short",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.OpenNonce = strings.Repeat("c", 31) },
			wantMsg: "open_nonce is not the expected nonce shape",
		},
		{
			name:    "open nonce one hex long",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.OpenNonce = strings.Repeat("c", 33) },
			wantMsg: "open_nonce is not the expected nonce shape",
		},
		{
			name:    "open nonce uppercase hex",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.OpenNonce = strings.Repeat("C3", 16) },
			wantMsg: "open_nonce is not the expected nonce shape",
		},
		{
			name:    "recorder session not proxy",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.RecorderSession = "drive" },
			wantMsg: `recorder_session "drive" is not public-safe`,
		},
		{
			name:    "unlabeled policy hash",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.PolicyHash = "abc" },
			wantMsg: `policy_hash "abc" is not labeled`,
		},
		{
			name:    "signer epoch not hex key",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.SignerKeyEpoch = "epoch-1" },
			wantMsg: "signer_key_epoch is not a hex public key",
		},
		{
			name:    "signer epoch one hex short",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.SignerKeyEpoch = strings.Repeat("d", 63) },
			wantMsg: "signer_key_epoch is not a hex public key",
		},
		{
			name:    "signer epoch one hex long",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.SignerKeyEpoch = strings.Repeat("d", 65) },
			wantMsg: "signer_key_epoch is not a hex public key",
		},
		{
			name:    "signer epoch uppercase hex",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.SignerKeyEpoch = strings.Repeat("D4", 32) },
			wantMsg: "signer_key_epoch is not a hex public key",
		},
		{
			name:    "nonzero heartbeat seconds",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.HeartbeatSeconds = 30 },
			wantMsg: "heartbeat_seconds = 30, want 0",
		},
		{
			name:    "chain open seq mismatch",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.ChainOpenSeq = 7 },
			wantMsg: "chain_open_seq does not match chain_seq",
		},
		{
			name:    "chain open seq zero at nonzero chain seq",
			mutate:  func(ar *receipt.ActionRecord) { ar.ChainSeq = 5 },
			wantMsg: "chain_open_seq does not match chain_seq",
		},
		{
			name:    "genesis differs from prev hash",
			mutate:  func(ar *receipt.ActionRecord) { ar.ChainPrevHash = "g1:" + strings.Repeat("f6", 32) },
			wantMsg: "genesis hash is not the expected g1 shape",
		},
		{
			name: "genesis bad shape",
			mutate: func(ar *receipt.ActionRecord) {
				ar.ChainPrevHash = strings.Repeat("b2", 32)
				ar.SessionControl.Open.GenesisHash = ar.ChainPrevHash
			},
			wantMsg: "genesis hash is not the expected g1 shape",
		},
		{
			name: "genesis body one hex short",
			mutate: func(ar *receipt.ActionRecord) {
				ar.ChainPrevHash = "g1:" + strings.Repeat("b", 63)
				ar.SessionControl.Open.GenesisHash = ar.ChainPrevHash
			},
			wantMsg: "genesis hash is not the expected g1 shape",
		},
		{
			name: "genesis body one hex long",
			mutate: func(ar *receipt.ActionRecord) {
				ar.ChainPrevHash = "g1:" + strings.Repeat("b", 65)
				ar.SessionControl.Open.GenesisHash = ar.ChainPrevHash
			},
			wantMsg: "genesis hash is not the expected g1 shape",
		},
		{
			name: "genesis body uppercase hex",
			mutate: func(ar *receipt.ActionRecord) {
				ar.ChainPrevHash = "g1:" + strings.Repeat("B2", 32)
				ar.SessionControl.Open.GenesisHash = ar.ChainPrevHash
			},
			wantMsg: "genesis hash is not the expected g1 shape",
		},
		{
			name:    "prior chain head set",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.PriorChainHead = "h" },
			wantMsg: "unsupported public-gallery binding fields",
		},
		{
			name:    "prior chain seq set",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.PriorChainSeq = 3 },
			wantMsg: "unsupported public-gallery binding fields",
		},
		{
			name:    "genesis anchor log set",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.GenesisAnchorLog = "log.vendor.example" },
			wantMsg: "unsupported public-gallery binding fields",
		},
		{
			name:    "contained uid set",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.ContainedUID = "1000" },
			wantMsg: "unsupported public-gallery binding fields",
		},
		{
			name:    "genesis anchor head set",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.GenesisAnchorHead = "h" },
			wantMsg: "unsupported public-gallery binding fields",
		},
		{
			name:    "posture capsule hash set",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.PostureCapsuleSHA256 = strings.Repeat("e5", 32) },
			wantMsg: "unsupported public-gallery binding fields",
		},
		{
			name:    "posture signer key id set",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.PostureSignerKeyID = "k1" },
			wantMsg: "unsupported public-gallery binding fields",
		},
		{
			name:    "containment nonce set",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionControl.Open.ContainmentNonce = strings.Repeat("f6", 16) },
			wantMsg: "unsupported public-gallery binding fields",
		},
		{
			name:    "disallowed context field",
			mutate:  func(ar *receipt.ActionRecord) { ar.SessionID = "sess-1" },
			wantMsg: "disallowed field session_id is populated",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ar := safeSessionOpenRecord()
			tt.mutate(&ar)
			err := ValidateReceiptPublicSafe(ar)
			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("expected session_open record to pass, got %v", err)
				}
				return
			}
			if !errors.Is(err, errAllowlist) {
				t.Fatalf("expected errAllowlist, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q does not contain %q", err, tt.wantMsg)
			}
		})
	}
}

func TestValidateSafeTarget_ParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		wantMsg string
	}{
		{name: "positive control reserved suffix", target: "https://api.vendor.example/v1"},
		{name: "positive control bare reserved host uppercase", target: "https://EXAMPLE.ORG/path"},
		{name: "unparseable", target: "http://[::1", wantMsg: "unparseable target"},
		{name: "no host", target: "file:///etc/hosts", wantMsg: "has no host"},
		{name: "empty", target: "", wantMsg: "empty target"},
		{name: "real host", target: "https://vendor.com/x", wantMsg: "is not a reserved/synthetic name"},
		{name: "reserved label mid host", target: "https://api.example.evil.com/x", wantMsg: "is not a reserved/synthetic name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateSafeTarget(tt.target)
			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("expected %q to pass, got %v", tt.target, err)
				}
				return
			}
			if !errors.Is(err, errAllowlist) {
				t.Fatalf("expected errAllowlist, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q does not contain %q", err, tt.wantMsg)
			}
		})
	}
}

// safeReservedHost accepts a bare reserved name or a host ending in a
// reserved suffix. A reserved label anywhere else in a real host must not
// count.
func TestSafeReservedHost_ExactAndSuffix(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"example.com":          true,
		"Example.NET":          true,
		"example.org":          true,
		"api.example.com":      true,
		"svc.vendor.test":      true,
		"notexample.com":       false,
		"example.company":      false,
		"api.example.evil.com": false,
		"foo.test.vendor.com":  false,
		"example.com.evil.net": false,
		"example.com.":         false,
		"xn--exmple-cua.com":   false,
	} {
		if got := safeReservedHost(host); got != want {
			t.Errorf("safeReservedHost(%q) = %v, want %v", host, got, want)
		}
	}
}
