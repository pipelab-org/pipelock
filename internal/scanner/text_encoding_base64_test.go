// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestTextEncodingMixedBase64Separators(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	key := "xoxb-" + "1234567890abcdef"
	mixed := mixedBase64Fixture(t, key)
	for _, sep := range []string{":", "!", ";"} {
		t.Run(sep, func(t *testing.T) {
			var groups []string
			for i := 0; i < len(mixed); i += 4 {
				groups = append(groups, mixed[i:min(i+4, len(mixed))])
			}
			carrier := strings.Join(groups, sep)
			result := s.ScanTextForDLP(t.Context(), carrier)
			for _, m := range result.Matches {
				if m.PatternName == "Slack Token" {
					return
				}
			}
			t.Fatalf("mixed base64 credential not detected: %+v", result)
		})
	}
}

func TestTextEncodingMixedBase64ReassemblyLimit(t *testing.T) {
	for _, size := range []int{maxReassembledTokenLen, maxReassembledTokenLen + 4} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			plaintext := "???~~~" + strings.Repeat("a", size/4*3-6)
			mixed := strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(plaintext)), "/", "_")
			var groups []string
			for i := 0; i < len(mixed); i += 4 {
				groups = append(groups, mixed[i:min(i+4, len(mixed))])
			}
			found := false
			for _, view := range decodeEncodings(strings.Join(groups, ":")) {
				if view.encoding == encodingBase64 && view.text == plaintext {
					found = true
				}
			}
			if want := size <= maxReassembledTokenLen; found != want {
				t.Fatalf("decoded=%v want=%v at reassembly size %d", found, want, size)
			}
		})
	}
}
