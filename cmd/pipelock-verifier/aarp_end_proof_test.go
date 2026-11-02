// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
)

func aarpChainFixtures(t *testing.T) ([]aarp.Envelope, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := aarp.NewEd25519Signer(testAARPKeyID, "mediator", priv)
	if err != nil {
		t.Fatal(err)
	}
	var stream []aarp.Envelope
	prior := aarp.GenesisPriorHash
	for i := range 3 {
		e := aarp.Envelope{
			Subject:   aarp.Subject{ActionRecordSHA256: strings.Repeat("a", 64), ReceiptEnvelopeSHA256: strings.Repeat("b", 64), ReceiptSignerKey: hex.EncodeToString(pub), ReceiptType: aarp.ReceiptTypeActionV1},
			Assertion: aarp.Assertion{Claimed: []string{"mediated"}, MediatorID: testAARPMediator, IssuedAt: testAARPIssued},
			Chain:     &aarp.ChainLink{IssuerID: "issuer.example", Seq: strconv.Itoa(i), PriorHash: prior},
		}
		e, err = aarp.Sign(e, signer)
		if err != nil {
			t.Fatal(err)
		}
		stream = append(stream, e)
		prior, err = e.PayloadDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	trust := filepath.Join(t.TempDir(), "trust.json")
	writeFileT(t, trust, mustJSON(t, trustFile{TrustedKeys: map[string]string{testAARPKeyID: hex.EncodeToString(pub)}}))
	return stream, trust
}

func TestAARPEndProofCorpus(t *testing.T) {
	dir := "../../sdk/conformance/testdata/aarp-end-proof"
	data, err := os.ReadFile(filepath.Join(dir, "expect.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Trust string
		Cases []struct {
			Name, File string
			Flags      []string
			Exit       int
			Status     string
			Proven     bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("empty AARP endpoint corpus")
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			cmd := newAARPCmd()
			var out, stderr bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&stderr)
			args := []string{filepath.Join(dir, tc.File), "--chain", "--json", "--trust", filepath.Join(dir, corpus.Trust)}
			cmd.SetArgs(append(args, tc.Flags...))
			err := cmd.Execute()
			if tc.Exit == 0 {
				if err != nil {
					t.Fatalf("exit: %v\n%s", err, out.String())
				}
			} else {
				assertExitCode(t, err, tc.Exit)
			}
			if tc.Exit == exitUsage {
				return
			}
			var report endproof.Report
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatalf("output: %v\n%s", err, out.String())
			}
			if report.Status != tc.Status || report.EndProof.Proven != tc.Proven {
				t.Fatalf("report: %+v; want %s / proven=%t", report, tc.Status, tc.Proven)
			}
		})
	}
}

func TestAARPChainAuthenticatedBoundary(t *testing.T) {
	stream, trust := aarpChainFixtures(t)
	for _, tc := range []struct {
		name           string
		start, end     int
		forge, noTrust bool
		want           int
	}{
		{"unbounded", 0, 3, false, false, 3},
		{"tail", 0, 2, false, false, 3},
		{"head", 1, 3, false, false, 1},
		{"signature", 0, 3, true, false, 1},
		{"unknown-key", 0, 3, false, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := append([]aarp.Envelope(nil), stream[tc.start:tc.end]...)
			if tc.forge {
				chain[0].Signatures = append([]aarp.Signature(nil), chain[0].Signatures...)
				chain[0].Signatures[0].Sig = strings.Repeat("A", 86)
			}
			path := filepath.Join(t.TempDir(), "chain.jsonl")
			writeFileT(t, path, chainJSONL(t, chain...))
			opts := aarpOptions{trustPath: trust, chain: true, jsonOutput: true}
			if tc.noTrust {
				opts.trustPath = ""
			}
			var out, stderr bytes.Buffer
			err := runAARP(&out, &stderr, path, opts)
			assertExitCode(t, err, tc.want)
			if tc.want == 3 && !strings.Contains(out.String(), "VALID PREFIX, END UNPROVEN") {
				t.Fatalf("missing prefix status: %s", out.String())
			}
			if tc.noTrust {
				var report aarpChainReport
				if err := json.Unmarshal(out.Bytes(), &report); err != nil {
					t.Fatalf("parse no-trust report: %v\n%s", err, out.String())
				}
				if !strings.Contains(report.Error, "--trust") {
					t.Fatalf("no-trust error %q does not name --trust", report.Error)
				}
			}
		})
	}
}
