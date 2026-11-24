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
	for _, input := range []string{base64.StdEncoding.EncodeToString([]byte(url)), hex.EncodeToString([]byte(url))} {
		got := s.ScanTextForDLP(t.Context(), input)
		if got.Clean || !HasEnforcingMatch(got.Matches) {
			t.Fatalf("decoded URL lost card enforcement: %+v", got)
		}
	}
}
