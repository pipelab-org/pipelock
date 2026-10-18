// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScanTextForDLP_JunkPercentEscapeInsideCredential(t *testing.T) {
	s := MustNew(config.Defaults())
	defer s.Close()
	key := "AKIA" + "IOSFODNN7" + "EXAMPLQ"
	for _, text := range []string{
		"AKIA%zz%49OSFODNN7EXAMPLQ",
		"AKIA%zzIOSFODNN7EXAMPLQ",
		"AKIAIOSF%G1ODNN7EXAMPLQ",
		"key=AKIA%%49OSFODNN7EXAMPLQ",
		"AKIA%%IOSFODNN7EXAMPLQ",
		"AKIA%4IOSFODNN7EXAMPLQ",
		"AKIA%zIOSFODNN7EXAMPLQ",
		"AKIA%IOSFODNN7EXAMPLQ",
		"AKIA%%%IOSFODNN7EXAMPLQ",
		"AKIA%zzz%IOSFODNN7EXAMPLQ",
		"AKIA%-!IOSFODNN7EXAMPLQ",
	} {
		if r := s.ScanTextForDLP(context.Background(), text); r.Clean {
			t.Errorf("credential with junk escapes not detected in %q", text)
		}
	}
	for _, text := range []string{
		"100% sure", "50%off and 20%zz discount", "progress 7%: " + key[:6],
		"100% done, 50%off, 20%zz of %s and %d",
		"SELECT * FROM t WHERE a LIKE '%foo%'",
	} {
		if r := s.ScanTextForDLP(context.Background(), text); !r.Clean {
			t.Errorf("benign percent text flagged %q: %+v", text, r.Matches)
		}
	}
}

func TestDropInvalidPercentEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"AKIA%zz%49X": "AKIA%49X",
		"a%41b":       "a%41b",
		"a%":          "a",
		"a%z":         "a",
		"a%%41":       "a%41",
		"plain":       "plain",
	} {
		if got := dropInvalidPercentEscapes(in); got != want {
			t.Errorf("dropInvalidPercentEscapes(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInvalidPercentEscapeViews(t *testing.T) {
	for in, want := range map[string][]string{
		"A%%B":    {"AB", "A"},
		"A%zB":    {"AzB", "A"},
		"A%-!B":   {"A-!B", "AB"},
		"A%zzz%B": {"AzzzB", "Az"},
		"A%41B":   {"A%41B", "A%41B"},
	} {
		got := invalidPercentEscapeViews(in)
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("view %d of %q = %q, want %q", i, in, got[i], want[i])
			}
		}
	}
}
