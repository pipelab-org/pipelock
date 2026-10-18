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
