// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScanTextForDLP_HexCredentialSplitAcrossValues(t *testing.T) {
	s := MustNew(config.Defaults())
	defer s.Close()
	h := hex.EncodeToString([]byte("AKIA" + "IOSFODNN7" + "EXAMPLQ"))
	a, b := h[:20], h[20:]
	for _, text := range []string{
		`["note", "` + a + `", "` + b + `", "done"]`,
		"id: 7\n" + a + "\n" + b + "\nend",
	} {
		if r := s.ScanTextForDLP(context.Background(), text); r.Clean {
			t.Errorf("split hex credential not detected in %q", text)
		}
	}
	// Adjacent hex that does not decode to a credential stays clean.
	if r := s.ScanTextForDLP(context.Background(), `["deadbeefcafe", "0123456789abcdef"]`); !r.Clean {
		t.Errorf("benign adjacent hex flagged: %+v", r.Matches)
	}
}

func TestScanTextForDLP_DecodedViewsPreserveCardPartition(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	cardHex := hex.EncodeToString([]byte(card))
	keyHex := hex.EncodeToString([]byte("AKIA" + "IOSFODNN7" + "EXAMPLQ"))
	for _, text := range []string{
		"card-%zz" + card,
		cardHex[:16] + " " + cardHex[16:],
	} {
		// The original typed document owns card evidence. Its additional
		// non-card view must neither reclassify cards nor stop at one before
		// inspecting a later non-card credential.
		if got := s.ScanTextForDLPWithTypedCardView(t.Context(), text, ""); !got.Clean || len(got.Matches) != 0 {
			t.Fatalf("non-card view produced card enforcement: %+v", got.Matches)
		}
		withKey := text + " separator " + keyHex[:20] + " " + keyHex[20:]
		got := s.ScanTextForDLPWithTypedCardView(t.Context(), withKey, "")
		found := false
		for _, match := range got.Matches {
			if match.genericCard {
				t.Fatal("decoded card escaped the non-card partition")
			}
			found = found || match.PatternName == "AWS Access ID"
		}
		if got.Clean || !found {
			t.Fatal("decoded card suppressed a later split credential")
		}
	}
}
