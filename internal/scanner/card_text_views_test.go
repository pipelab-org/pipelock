// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCardTextViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	pan := cardtest.Issuer("401900000000000", 16)
	if !validateLuhn(pan) {
		t.Fatal("invalid test card")
	}
	for _, tc := range []struct {
		name, text string
		block      bool
	}{
		{"decimal cell", "F27=" + pan[:4] + "." + pan[4:], false},
		{"tab columns", pan[:8] + "\t" + pan[8:], false},
		{"newline columns", pan[:8] + "\n" + pan[8:], false},
		{"space columns", pan[:8] + " " + pan[8:], false},
		{"version", "version 2026.11.24", false},
		{"card shaped version components", "version " + pan[:4] + "." + pan[4:8] + "." + pan[8:], false},
		{"bare", pan, true},
		{"JSON string", `{"x":"` + pan + `"}`, true},
		{"grouped", strings.Join([]string{pan[:4], pan[4:8], pan[8:12], pan[12:]}, "-"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.ScanTextForDLP(t.Context(), tc.text)
			if got.Clean == tc.block {
				t.Errorf("block=%t, result=%+v", tc.block, got)
			}
		})
	}
}
