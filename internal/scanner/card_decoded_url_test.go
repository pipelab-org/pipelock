// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDecodedCardURLChannel(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	pan := cardtest.Issuer("4019", 16)
	url := "https://api.vendor.example/path/" + pan[:4] + "." + pan[4:]
	for _, input := range []string{
		base64.StdEncoding.EncodeToString([]byte(url)),
		hex.EncodeToString([]byte(url)),
		"https://api.vendor.example/%ZZ/" + pan[:4] + "." + pan[4:],
		"https://api.vendor.example/%ZZ/?a=" + pan[:8] + "&b=" + pan[8:],
		"https%3A%2F%2Fapi.vendor.example%2Fpath%2F" + pan[:4] + "." + pan[4:],
		"https&#58;//api.vendor.example/path/" + pan[:4] + "." + pan[4:],
	} {
		got := s.ScanTextForDLP(t.Context(), input)
		if got.Clean || !HasEnforcingMatch(got.Matches) {
			t.Fatalf("decoded or malformed URL lost card enforcement for %q: %+v", input, got)
		}
	}
	// Reassembly lane admission must accept underscore-flanked canonical cards
	// even though RE2's \b treats '_' as a word character.
	g4 := pan[:4] + "_" + pan[4:8] + "_" + pan[8:12] + "_" + pan[12:]
	for _, plain := range []string{"1234_" + g4, "4242_4242_4242_4242_" + g4, g4 + "_1234", "1234__" + pan[:4] + "__" + pan[4:8] + "__" + pan[8:12] + "__" + pan[12:]} {
		wire := reassemblyBang(base64.StdEncoding.EncodeToString([]byte(plain)))
		budget := assembledBudget{patterns: textDLPCardPatterns}
		res := assembledLayer(s.reassemblyPlan, wire, &budget, 0)
		if !HasEnforcingMatch(res.findings) {
			t.Fatalf("reassembly lane dropped underscore-flanked card %q: %+v", plain, res.findings)
		}
	}
}
