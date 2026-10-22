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

func TestScanTextForDLP_SplitHexWarningDoesNotHideBlock(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{Name: "Advisory marker", Regex: "advisorymarker", Severity: config.SeverityLow, Action: config.ActionWarn},
		config.DLPPattern{Name: "Enforced marker", Regex: "enforcedmarker", Severity: config.SeverityHigh},
	)
	s := MustNew(cfg)
	defer s.Close()
	split := func(value string) string {
		h := hex.EncodeToString([]byte(value))
		return h[:12] + " " + h[12:]
	}
	for _, tc := range []struct {
		name, text string
		blocked    bool
	}{
		{"warn only", split("advisorymarker"), false},
		{"warn before block", split("advisorymarker") + " separator " + split("enforcedmarker"), true},
		{"block before warn", split("enforcedmarker") + " separator " + split("advisorymarker"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := s.ScanTextForDLP(context.Background(), tc.text)
			if r.Clean == tc.blocked {
				t.Fatalf("clean=%v want blocked=%v matches=%+v", r.Clean, tc.blocked, r.Matches)
			}
			if len(r.Matches)+len(r.InformationalMatches) == 0 {
				t.Fatal("split-hex findings lost")
			}
		})
	}
}
