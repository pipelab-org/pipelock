// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package coveragecertverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/coveragecert"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func writeCoverageCertVerifyFixture(t *testing.T) (certFile, pubHex string) {
	return writeCoverageCertVerifyStatusFixture(t, "LIMITED", "bounded_closed", true,
		"proxy.run.0123456789abcdef0123456789abcdef")
}

func writeCoverageCertVerifyStatusFixture(t *testing.T, status, reason string, chainIntact bool, sessionID string) (certFile, pubHex string) {
	t.Helper()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var chainGaps uint64
	if !chainIntact {
		chainGaps = 1
	}
	cert, err := coveragecert.Sign(coveragecert.Body{
		Schema:        coveragecert.Schema,
		KeyPurpose:    coveragecert.KeyPurpose,
		Agent:         "agent-a",
		WindowStart:   start,
		WindowEnd:     start.Add(time.Hour),
		TotalReceipts: 2,
		ChainGaps:     chainGaps,
		Sessions: []coveragecert.SessionCoverage{{
			ID:                 sessionID,
			ReceiptCount:       2,
			ChainIntact:        chainIntact,
			Anchored:           "local",
			CompletenessStatus: status,
			CompletenessReason: reason,
		}},
		SessionsCovered:    1,
		ChainsIntact:       boolCount(chainIntact),
		ChainsBroken:       boolCount(!chainIntact),
		TrustedSignerKey:   hex.EncodeToString(pub),
		Boundary:           coveragecert.DefaultBoundary(),
		StandingExclusions: coveragecert.DefaultStandingExclusions(),
	}, priv)
	if err != nil {
		t.Fatalf("coveragecert.Sign: %v", err)
	}
	data, err := coveragecert.Marshal(cert)
	if err != nil {
		t.Fatalf("coveragecert.Marshal: %v", err)
	}
	certFile = filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(certFile, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return certFile, hex.EncodeToString(pub)
}

func writeCoverageCertInvalidBodyFixture(t *testing.T) (certFile, pubHex string) {
	t.Helper()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubHex = hex.EncodeToString(pub)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := coveragecert.Body{
		Schema:        coveragecert.Schema,
		KeyPurpose:    coveragecert.KeyPurpose,
		Agent:         "agent-a",
		WindowStart:   start,
		WindowEnd:     start.Add(time.Hour),
		TotalReceipts: 2,
		Sessions: []coveragecert.SessionCoverage{{
			ID:                 "session-a",
			ReceiptCount:       2,
			ChainIntact:        true,
			Anchored:           "local",
			CompletenessStatus: "LIMITED",
			CompletenessReason: "abnormal_end",
		}},
		SessionsCovered:    1,
		ChainsIntact:       1,
		TrustedSignerKey:   pubHex,
		Boundary:           "Coverage of all agent activity and mediated egress inside the declared Pipelock boundary",
		StandingExclusions: coveragecert.DefaultStandingExclusions(),
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	cert := coveragecert.Certificate{
		Body:      body,
		Signature: hex.EncodeToString(ed25519.Sign(priv, preimage)),
		SignerKey: pubHex,
	}
	data, err := coveragecert.Marshal(cert)
	if err != nil {
		t.Fatalf("coveragecert.Marshal: %v", err)
	}
	certFile = filepath.Join(t.TempDir(), "invalid-body-cert.json")
	if err := os.WriteFile(certFile, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return certFile, pubHex
}

func TestRunTrustedSignerVerifies(t *testing.T) {
	certFile, pubHex := writeCoverageCertVerifyFixture(t)
	var out bytes.Buffer

	if err := Run(Options{
		CertFile:       certFile,
		TrustedSigners: []string{"inline=" + pubHex},
		Out:            &out,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.String(), "Signature: valid") || !strings.Contains(out.String(), "CHAIN VALID") {
		t.Fatalf("Run output = %q, want bounded verification lines", out.String())
	}
}

func TestRunCertificateEndProofStatus(t *testing.T) {
	tests := []struct {
		name        string
		status      string
		reason      string
		chainIntact bool
		sessionID   string
		wantStatus  string
		wantErr     bool
	}{
		{
			name:   "bounded run close proves end",
			status: "LIMITED", reason: "bounded_closed", chainIntact: true,
			sessionID:  "proxy.run.0123456789abcdef0123456789abcdef",
			wantStatus: "CHAIN VALID",
		},
		{
			name:   "abnormal end is partial",
			status: "LIMITED", reason: "abnormal_end", chainIntact: true, sessionID: "session-a",
			wantStatus: "VALID PREFIX, END UNPROVEN", wantErr: true,
		},
		{
			name:   "broken chain fails",
			status: "BROKEN", reason: "chain_broken", chainIntact: false, sessionID: "session-a",
			wantStatus: "CHAIN BROKEN", wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certFile, pubHex := writeCoverageCertVerifyStatusFixture(t, tc.status, tc.reason, tc.chainIntact, tc.sessionID)
			var out bytes.Buffer
			err := Run(Options{CertFile: certFile, TrustedSigners: []string{"inline=" + pubHex}, Out: &out})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Run err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && tc.wantStatus == "VALID PREFIX, END UNPROVEN" {
				var exit *cliutil.ExitError
				if !errors.As(err, &exit) || exit.Code != 3 {
					t.Fatalf("Run err = %v, want exit code 3", err)
				}
			}
			if !strings.Contains(out.String(), tc.wantStatus) {
				t.Fatalf("Run output = %q, want %q", out.String(), tc.wantStatus)
			}
		})
	}
}

func TestCertificateEndProofAggregatesEverySession(t *testing.T) {
	closed := coveragecert.SessionCoverage{
		ID: "proxy.run.0123456789abcdef0123456789abcdef", ChainIntact: true,
		CompletenessStatus: "LIMITED", CompletenessReason: "bounded_closed",
	}
	incomplete := coveragecert.SessionCoverage{
		ID: "session-a", ChainIntact: true,
		CompletenessStatus: "LIMITED", CompletenessReason: "abnormal_end",
	}
	broken := coveragecert.SessionCoverage{
		ID: "session-b", ChainIntact: false,
		CompletenessStatus: "BROKEN", CompletenessReason: "chain_broken",
	}
	tests := []struct {
		name       string
		sessions   []coveragecert.SessionCoverage
		wantStatus string
		wantValid  string
		wantProof  bool
	}{
		{name: "empty certificate is partial", sessions: nil, wantStatus: "VALID PREFIX, END UNPROVEN", wantValid: "valid"},
		{name: "later incomplete session prevents aggregate proof", sessions: []coveragecert.SessionCoverage{closed, incomplete}, wantStatus: "VALID PREFIX, END UNPROVEN", wantValid: "valid"},
		{name: "earlier incomplete session does not hide later broken session", sessions: []coveragecert.SessionCoverage{incomplete, broken}, wantStatus: "CHAIN BROKEN", wantValid: "invalid"},
		{name: "earlier close does not hide later broken session", sessions: []coveragecert.SessionCoverage{closed, broken}, wantStatus: "CHAIN BROKEN", wantValid: "invalid"},
		{name: "every bounded run has a close", sessions: []coveragecert.SessionCoverage{closed, closed}, wantStatus: "CHAIN VALID", wantValid: "valid", wantProof: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := certificateEndProof(coveragecert.Body{Sessions: tc.sessions})
			if got.Status != tc.wantStatus || got.Integrity != tc.wantValid || got.EndProof.Proven != tc.wantProof {
				t.Fatalf("certificateEndProof() = %+v, want status=%q integrity=%q proven=%v", got, tc.wantStatus, tc.wantValid, tc.wantProof)
			}
		})
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestRunNoTrustedSignerFailsClosedByDefault(t *testing.T) {
	certFile, _ := writeCoverageCertVerifyFixture(t)
	var out bytes.Buffer

	err := Run(Options{
		CertFile: certFile,
		Out:      &out,
	})
	if err == nil || !strings.Contains(err.Error(), "no trusted-signer set supplied") {
		t.Fatalf("Run err = %v, want fail-closed missing trusted-signer error", err)
	}
	if strings.Contains(out.String(), "STRUCTURAL ONLY") {
		t.Fatalf("Run output = %q, must not label default verification as structural-only opt-in", out.String())
	}
}

func TestRunTrustModeTable(t *testing.T) {
	certFile, pubHex := writeCoverageCertVerifyFixture(t)
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPubHex := hex.EncodeToString(otherPub)

	tests := []struct {
		name             string
		trustedSigners   []string
		allowStructural  bool
		wantErrContains  string
		wantOutContains  []string
		rejectOutContain []string
	}{
		{
			name:            "no trusted set no flag fails nonzero",
			wantErrContains: "no trusted-signer set supplied",
			wantOutContains: []string{"Signature: valid", "Signer: NOT TRUSTED"},
		},
		{
			name:            "no trusted set structural flag exits zero",
			allowStructural: true,
			wantOutContains: []string{"Signature: valid", "Signer: NOT TRUSTED", "STRUCTURAL ONLY — signer NOT trusted"},
		},
		{
			name:             "trusted set matching signer verifies",
			trustedSigners:   []string{"inline=" + pubHex},
			wantOutContains:  []string{"Signature: valid", "Signer: TRUSTED"},
			rejectOutContain: []string{"STRUCTURAL ONLY"},
		},
		{
			name:            "trusted set wrong signer fails",
			trustedSigners:  []string{"inline=" + otherPubHex},
			wantErrContains: "not in the trusted-signer set",
			wantOutContains: []string{"Signature: valid", "Signer: NOT TRUSTED"},
		},
		{
			name:            "forged self-signed cert fails by default",
			wantErrContains: "no trusted-signer set supplied",
			wantOutContains: []string{"Signature: valid", "Signer: NOT TRUSTED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := Run(Options{
				CertFile:       certFile,
				TrustedSigners: tt.trustedSigners,
				AllowUnpinned:  tt.allowStructural,
				Out:            &out,
			})
			if tt.wantErrContains == "" {
				if err != nil {
					t.Fatalf("Run err = %v, want nil", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Fatalf("Run err = %v, want containing %q", err, tt.wantErrContains)
			}
			for _, want := range tt.wantOutContains {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("Run output = %q, want containing %q", out.String(), want)
				}
			}
			for _, reject := range tt.rejectOutContain {
				if strings.Contains(out.String(), reject) {
					t.Fatalf("Run output = %q, must not contain %q", out.String(), reject)
				}
			}
		})
	}
}

func TestRunUntrustedSignerFailsClosed(t *testing.T) {
	certFile, _ := writeCoverageCertVerifyFixture(t)
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var out bytes.Buffer

	err = Run(Options{
		CertFile:       certFile,
		TrustedSigners: []string{"inline=" + hex.EncodeToString(otherPub)},
		Out:            &out,
	})
	if err == nil || !strings.Contains(err.Error(), "not in the trusted-signer set") {
		t.Fatalf("Run err = %v, want fail-closed untrusted-signer error", err)
	}
	// The diagnostic line is still emitted before the fail-closed return.
	if !strings.Contains(out.String(), "NOT TRUSTED") {
		t.Fatalf("Run output = %q, want NOT TRUSTED diagnostic line", out.String())
	}
}

func TestRunInvalidBodyFailsClosedEvenWithTrustedSignature(t *testing.T) {
	certFile, pubHex := writeCoverageCertInvalidBodyFixture(t)
	var out bytes.Buffer

	err := Run(Options{
		CertFile:       certFile,
		TrustedSigners: []string{"inline=" + pubHex},
		Out:            &out,
	})
	if err == nil || !strings.Contains(err.Error(), "body validation failed") {
		t.Fatalf("Run invalid body err = %v, want body validation failure", err)
	}
}

func TestRunRejectsSignedAgentLineInjection(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := coveragecert.Body{
		Schema:        coveragecert.Schema,
		KeyPurpose:    coveragecert.KeyPurpose,
		Agent:         "agent-a\nFORGED: sessions covered",
		WindowStart:   start,
		WindowEnd:     start.Add(time.Hour),
		TotalReceipts: 2,
		Sessions: []coveragecert.SessionCoverage{{
			ID:                 "session-a",
			ReceiptCount:       1,
			ChainIntact:        true,
			Anchored:           "local",
			CompletenessStatus: "LIMITED",
			CompletenessReason: "abnormal_end",
		}},
		SessionsCovered:    1,
		ChainsIntact:       1,
		TrustedSignerKey:   pubHex,
		Boundary:           coveragecert.DefaultBoundary(),
		StandingExclusions: coveragecert.DefaultStandingExclusions(),
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	cert := coveragecert.Certificate{
		Body:      body,
		Signature: hex.EncodeToString(ed25519.Sign(priv, preimage)),
		SignerKey: pubHex,
	}
	data, err := coveragecert.Marshal(cert)
	if err != nil {
		t.Fatalf("coveragecert.Marshal: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "line-injection-cert.json")
	if err := os.WriteFile(certFile, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var out bytes.Buffer
	err = Run(Options{
		CertFile:       certFile,
		TrustedSigners: []string{"inline=" + pubHex},
		Out:            &out,
	})
	if err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("Run line-injection err = %v, want fail-closed control-character error", err)
	}
	if strings.Contains(out.String(), "FORGED") {
		t.Fatalf("Run output = %q, must not emit injected over-claim lines", out.String())
	}
}

func TestRunFailsClosed(t *testing.T) {
	certFile, pubHex := writeCoverageCertVerifyFixture(t)
	data, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(data), `"agent": "agent-a"`, `"agent": "agent-b"`, 1)
	if tampered == string(data) {
		t.Fatal("fixture did not contain agent field")
	}
	tamperedFile := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(tamperedFile, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err = Run(Options{CertFile: tamperedFile, TrustedSigners: []string{"inline=" + pubHex}})
	if err == nil || !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("Run tampered error = %v, want invalid signature", err)
	}

	err = Run(Options{CertFile: filepath.Join(t.TempDir(), "missing.json")})
	if err == nil || !strings.Contains(err.Error(), "--cert") {
		t.Fatalf("Run missing file error = %v, want --cert", err)
	}
}

func TestRunRejectsOversizedCertificate(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(certFile, bytes.Repeat([]byte{'x'}, int(maxCertificateBytes)+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := Run(Options{CertFile: certFile})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Run oversized certificate err = %v, want bounded-read error", err)
	}
}

func TestRunRejectsNonRegularCertificate(t *testing.T) {
	err := Run(Options{CertFile: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Run directory certificate err = %v, want regular-file error", err)
	}
}
