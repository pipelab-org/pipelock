// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestProviderTokenStrictLeftBoundary(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	value := "tok_" + strings.Repeat("a1", 24)
	for _, prefix := range []string{".", "header.", "opaque_", "opaque-", "opaque"} {
		result := s.ScanTextForDLP(t.Context(), prefix+value)
		for _, m := range result.Findings() {
			if m.PatternName == "Together AI Key" {
				t.Errorf("embedded provider token matched prefix %q", prefix)
			}
		}
	}
	for _, prefix := range []string{"", " ", "\"", "="} {
		result := s.ScanTextForDLP(t.Context(), prefix+value)
		found := false
		for _, m := range result.Matches {
			found = found || m.PatternName == "Together AI Key"
		}
		if !found {
			t.Errorf("provider token lost after %q", prefix)
		}
	}
}
