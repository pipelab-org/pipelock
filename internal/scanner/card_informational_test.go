// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCardInformationalContinuation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	public := strings.Repeat("4242", 4)
	pan := cardtest.Issuer("4019", 16)
	for _, input := range []string{
		public + " " + base64.StdEncoding.EncodeToString([]byte(pan)),
		base64.StdEncoding.EncodeToString([]byte(public)) + " " + hex.EncodeToString([]byte(pan)),
		reassemblyBang(base64.StdEncoding.EncodeToString([]byte(public))) + " " + reassemblyBang(base64.StdEncoding.EncodeToString([]byte(pan))),
	} {
		got := s.ScanTextForDLP(t.Context(), input)
		if got.Clean || !HasEnforcingMatch(got.Matches) {
			t.Fatalf("informational finding hid enforcing lane: %+v", got)
		}
		for _, m := range got.Matches {
			if m.IsInformational() {
				t.Fatal("informational finding in enforcement partition")
			}
		}
	}
	for _, input := range []string{public, `[4111,1111,1111,1111]`} {
		got := s.ScanTextForDLP(t.Context(), input)
		if !got.Clean || len(got.Matches) != 0 || !OnlyInformational(got.InformationalMatches) {
			t.Fatalf("partition invariant failed: %+v", got)
		}
	}
	splitPub := `["4242","4242","4242","4242"]`
	if runs := s.ScanJSONCardRuns(t.Context(), splitPub); !OnlyInformational(runs) {
		t.Fatalf("split public test PAN lost informational JSON run: %+v", runs)
	}
	splitBoth := `["4242","4242","4242","4242","` + pan[:4] + `","` + pan[4:8] + `","` + pan[8:12] + `","` + pan[12:] + `"]`
	if runs := s.ScanJSONCardRuns(t.Context(), splitBoth); !HasEnforcingMatch(runs) {
		t.Fatalf("split public test PAN shadowed real JSON card run: %+v", runs)
	}
}

func TestInformationalDeduplicationDominance(t *testing.T) {
	info := TextDLPMatch{PatternName: "card fixture", Encoded: "hex", Warn: true, informational: true}
	enforce := TextDLPMatch{PatternName: info.PatternName, Encoded: info.Encoded}
	for _, matches := range [][]TextDLPMatch{{info, enforce}, {enforce, info}} {
		got := deduplicateMatches(matches)
		if len(got) != 1 || got[0].IsInformational() {
			t.Fatal("informational evidence dominated enforcement")
		}
	}
	opts := textDLPOptions{patterns: textDLPCardPatterns}
	info.genericCard = true
	gate := newTextDLPDecodeGate(opts, []TextDLPMatch{info})
	if gate.done() {
		t.Fatal("informational match closed decode gate")
	}
	enforce.genericCard = true
	gate.close([]TextDLPMatch{enforce})
	if !gate.done() {
		t.Fatal("enforcing match did not close its gate")
	}
}

func TestCardFragmentTextBoundaries(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	pan := cardtest.Issuer("4019", 16)
	for _, sep := range []string{".", "\t", "\n", "\r", " "} {
		parts := []fragment{{data: []byte(pan[:8] + sep)}, {data: []byte(pan[8:])}}
		if got := scanFragmentsForSecrets(t.Context(), s, parts); len(got) > 0 {
			t.Errorf("column seam %q enforced: %+v", sep, got)
		}
	}
	if got := scanFragmentsForSecrets(t.Context(), s, []fragment{{data: []byte(pan[:8])}, {data: []byte(pan[8:])}}); len(got) == 0 {
		t.Fatal("contiguous card seam not enforced")
	}
}
